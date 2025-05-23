package io.springsecurity.springsecurity6x.security.statemachine.support;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * State Machine Context와 FactorContext 간의 변환을 담당하는 헬퍼 클래스
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class StateContextHelper {

    private final ContextPersistence contextPersistence;

    /**
     * StateContext에서 FactorContext 추출
     * 우선순위:
     * 1. ExtendedState에 저장된 FactorContext 객체
     * 2. ExtendedState 변수들로부터 재구성
     * 3. ContextPersistence를 통한 로드
     */
    public FactorContext extractFactorContext(StateContext<MfaState, MfaEvent> context) {
        ExtendedState extendedState = context.getExtendedState();
        Map<Object, Object> variables = extendedState.getVariables();

        // 1. 직접 저장된 FactorContext 확인
        Object storedContext = variables.get("factorContext");
        if (storedContext instanceof FactorContext) {
            return (FactorContext) storedContext;
        }

        // 2. 개별 변수들로부터 재구성
        String mfaSessionId = (String) variables.get("mfaSessionId");
        if (mfaSessionId == null) {
            throw new IllegalStateException("MFA session ID not found in state context");
        }

        // 3. Authentication 복원
        Authentication authentication = extractAuthentication(context, mfaSessionId);
        if (authentication == null) {
            throw new IllegalStateException("Authentication not found for session: " + mfaSessionId);
        }

        // 4. FactorContext 재구성
        MfaState currentState = extractCurrentState(variables);
        String flowTypeName = (String) variables.getOrDefault("flowTypeName", "mfa");

        FactorContext factorContext = new FactorContext(
                mfaSessionId,
                authentication,
                currentState,
                flowTypeName
        );

        // 5. 추가 필드 복원
        restoreFactorContextFields(factorContext, variables);

        return factorContext;
    }

    /**
     * Authentication 객체 복원
     * 우선순위:
     * 1. ExtendedState에 저장된 Authentication 객체
     * 2. ExtendedState의 인증 정보로부터 재구성
     * 3. ContextPersistence를 통한 로드
     */
    private Authentication extractAuthentication(StateContext<MfaState, MfaEvent> context,
                                                 String mfaSessionId) {
        Map<Object, Object> variables = context.getExtendedState().getVariables();

        // 1. 직접 저장된 Authentication 확인
        Object storedAuth = variables.get("primaryAuthentication");
        if (storedAuth instanceof Authentication) {
            return (Authentication) storedAuth;
        }

        // 2. 저장된 인증 정보로부터 재구성
        String principalName = (String) variables.get("principalName");
        if (principalName != null) {
            // SecurityContextHolder나 세션에서 복원 시도
            HttpServletRequest request = extractHttpServletRequest(context);
            if (request != null) {
                try {
                    FactorContext persistedContext = contextPersistence.loadContext(mfaSessionId, request);
                    if (persistedContext != null && persistedContext.getPrimaryAuthentication() != null) {
                        return persistedContext.getPrimaryAuthentication();
                    }
                } catch (Exception e) {
                    log.warn("Failed to load authentication from persistence: {}", e.getMessage());
                }
            }
        }

        // 3. 메시지 헤더에서 확인
        Object authHeader = context.getMessageHeader("authentication");
        if (authHeader instanceof Authentication) {
            return (Authentication) authHeader;
        }

        return null;
    }

    /**
     * FactorContext의 추가 필드들 복원
     */
    private void restoreFactorContextFields(FactorContext factorContext,
                                            Map<Object, Object> variables) {
        // 현재 팩터 정보
        factorContext.setCurrentStepId((String) variables.get("currentStepId"));

        // 현재 처리 중인 팩터 타입
        String currentFactorType = (String) variables.get("currentFactorType");
        if (currentFactorType != null) {
            try {
                factorContext.setCurrentProcessingFactor(AuthType.valueOf(currentFactorType));
            } catch (IllegalArgumentException e) {
                log.warn("Invalid currentFactorType: {}", currentFactorType);
            }
        }

        // 재시도 횟수
        Integer retryCount = (Integer) variables.get("retryCount");
        factorContext.setRetryCount(retryCount != null ? retryCount : 0);

        // 마지막 에러
        String lastError = (String) variables.get("lastError");
        if (lastError != null) {
            factorContext.setLastError(lastError);
        }

        // 타임스탬프 - FactorContext의 createdAt은 final long 타입이므로 setAttribute 사용
        Object createdAt = variables.get("createdAt");
        if (createdAt instanceof Long) {
            factorContext.setAttribute("createdAt", createdAt);
        } else if (createdAt instanceof String) {
            try {
                factorContext.setAttribute("createdAt", Long.parseLong((String) createdAt));
            } catch (NumberFormatException e) {
                log.warn("Invalid createdAt format: {}", createdAt);
            }
        }

        // 완료된 팩터 복원
        restoreCompletedFactors(factorContext, variables);

        // 사용 가능한 팩터 복원 - FactorContext에는 setAvailableFactors가 없으므로 attributes 사용
        restoreAvailableFactors(factorContext, variables);

        // 추가 데이터 복원
        restoreAdditionalData(factorContext, variables);
    }

    /**
     * 완료된 팩터 목록 복원
     */
    private void restoreCompletedFactors(FactorContext factorContext,
                                         Map<Object, Object> variables) {
        Object completedFactorsObj = variables.get("completedFactors");

        if (completedFactorsObj instanceof List) {
            // 이미 List<AuthenticationStepConfig> 형태인 경우
            List<AuthenticationStepConfig> completedFactors = (List<AuthenticationStepConfig>) completedFactorsObj;
            // FactorContext의 completedFactors는 final이므로 clear하고 addAll
            factorContext.getCompletedFactors().clear();
            factorContext.getCompletedFactors().addAll(completedFactors);
        } else if (completedFactorsObj instanceof String) {
            // 문자열로 직렬화된 경우 파싱
            String completedFactorsStr = (String) completedFactorsObj;
            if (!completedFactorsStr.isEmpty()) {
                List<AuthenticationStepConfig> configs = parseCompletedFactors(completedFactorsStr,
                        factorContext.getFlowTypeName());
                factorContext.getCompletedFactors().clear();
                factorContext.getCompletedFactors().addAll(configs);
            }
        }
    }

    /**
     * 완료된 팩터 문자열 파싱
     * 형식: "stepId1:type1:order1,stepId2:type2:order2"
     */
    private List<AuthenticationStepConfig> parseCompletedFactors(String completedFactorsStr,
                                                                 String flowTypeName) {
        return Arrays.stream(completedFactorsStr.split(","))
                .filter(s -> !s.isEmpty())
                .map(factorStr -> {
                    String[] parts = factorStr.split(":");
                    if (parts.length >= 2) {
                        AuthenticationStepConfig config = new AuthenticationStepConfig();
                        config.setStepId(parts[0]);
                        config.setType(parts[1]);
                        config.setOrder(parts.length > 2 ? Integer.parseInt(parts[2]) : 1);
                        config.setRequired(true);
                        config.setType(flowTypeName != null ? flowTypeName : "mfa");
                        return config;
                    }
                    return null;
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    /**
     * 사용 가능한 팩터 복원
     */
    private void restoreAvailableFactors(FactorContext factorContext,
                                         Map<Object, Object> variables) {
        Object availableFactorsObj = variables.get("availableFactors");

        if (availableFactorsObj instanceof Set) {
            @SuppressWarnings("unchecked")
            Set<AuthType> authTypes = (Set<AuthType>) availableFactorsObj;
            factorContext.setAttribute("availableFactors", authTypes);
        } else if (availableFactorsObj instanceof String) {
            String availableFactorsStr = (String) availableFactorsObj;
            if (!availableFactorsStr.isEmpty()) {
                Set<AuthType> authTypes = Arrays.stream(availableFactorsStr.split(","))
                        .map(String::trim)
                        .map(AuthType::valueOf)
                        .collect(Collectors.toSet());
                factorContext.setAttribute("availableFactors", authTypes);
            }
        }
    }

    /**
     * 추가 데이터 복원
     */
    private void restoreAdditionalData(FactorContext factorContext,
                                       Map<Object, Object> variables) {
        // additionalData로 시작하는 모든 변수를 추가 데이터로 복원
        variables.entrySet().stream()
                .filter(entry -> entry.getKey().toString().startsWith("additionalData."))
                .forEach(entry -> {
                    String key = entry.getKey().toString().substring("additionalData.".length());
                    factorContext.setAttribute(key, entry.getValue());
                });
    }

    /**
     * 현재 상태 추출
     */
    private MfaState extractCurrentState(Map<Object, Object> variables) {
        Object currentStateObj = variables.get("currentState");
        if (currentStateObj instanceof MfaState) {
            return (MfaState) currentStateObj;
        } else if (currentStateObj instanceof String) {
            return MfaState.valueOf((String) currentStateObj);
        }
        return MfaState.IDLE;
    }

    /**
     * HttpServletRequest 추출 (가능한 경우)
     */
    private HttpServletRequest extractHttpServletRequest(StateContext<MfaState, MfaEvent> context) {
        Object request = context.getMessageHeader("request");
        if (request instanceof HttpServletRequest) {
            return (HttpServletRequest) request;
        }
        return null;
    }

    /**
     * FactorContext를 StateContext에 저장
     */
    public void saveFactorContext(StateContext<MfaState, MfaEvent> context,
                                  FactorContext factorContext) {
        ExtendedState extendedState = context.getExtendedState();

        // FactorContext 객체 자체를 저장 (선택적)
        // extendedState.getVariables().put("factorContext", factorContext);

        // 개별 필드들도 저장 (호환성 유지)
        Map<Object, Object> variables = extendedState.getVariables();
        variables.put("mfaSessionId", factorContext.getMfaSessionId());
        variables.put("currentState", factorContext.getCurrentState());
        variables.put("flowTypeName", factorContext.getFlowTypeName());
        variables.put("currentStepId", factorContext.getCurrentStepId());

        // currentProcessingFactor 저장
        if (factorContext.getCurrentProcessingFactor() != null) {
            variables.put("currentFactorType", factorContext.getCurrentProcessingFactor().name());
        }

        variables.put("retryCount", factorContext.getRetryCount());
        variables.put("createdAt", factorContext.getCreatedAt());
        variables.put("lastError", factorContext.getLastError());

        // Authentication 정보 저장 (주요 정보만)
        if (factorContext.getPrimaryAuthentication() != null) {
            variables.put("principalName", factorContext.getPrimaryAuthentication().getName());
        }

        // 복잡한 객체들은 문자열로 직렬화
        if (factorContext.getCompletedFactors() != null && !factorContext.getCompletedFactors().isEmpty()) {
            String completedFactorsStr = serializeCompletedFactors(factorContext.getCompletedFactors());
            variables.put("completedFactors", completedFactorsStr);
        }

        // availableFactors는 attributes에서 가져오기
        Object availableFactors = factorContext.getAttribute("availableFactors");
        if (availableFactors instanceof Set) {
            @SuppressWarnings("unchecked")
            Set<AuthType> authTypes = (Set<AuthType>) availableFactors;
            String availableFactorsStr = authTypes.stream()
                    .map(AuthType::name)
                    .collect(Collectors.joining(","));
            variables.put("availableFactors", availableFactorsStr);
        }
    }

    /**
     * 완료된 팩터 직렬화
     */
    private String serializeCompletedFactors(List<AuthenticationStepConfig> completedFactors) {
        return completedFactors.stream()
                .map(config -> String.format("%s:%s:%d",
                        config.getStepId(),
                        config.getType(),
                        config.getOrder()))
                .collect(Collectors.joining(","));
    }
}