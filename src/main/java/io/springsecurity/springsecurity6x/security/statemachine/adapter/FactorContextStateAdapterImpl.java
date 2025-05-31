package io.springsecurity.springsecurity6x.security.statemachine.adapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * FactorContext와 State Machine 간의 완전한 데이터 변환 어댑터
 * State Machine을 단일 진실의 원천으로 사용
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class FactorContextStateAdapterImpl implements FactorContextStateAdapter {

    private final ObjectMapper objectMapper;

    @Override
    public Map<Object, Object> toStateMachineVariables(FactorContext factorContext) {
        // 절대 null을 반환하지 않도록 보장
        Map<Object, Object> variables = new HashMap<>();

        try {
            if (factorContext == null) {
                log.error("FactorContext is null in toStateMachineVariables");
                variables.put("_error", "null_factor_context");
                return variables;
            }

            // 필수 필드 - null-safe 추가
            putSafely(variables, "mfaSessionId", factorContext.getMfaSessionId(), "unknown");
            putSafely(variables, "username", factorContext.getUsername(), "unknown");
            putSafely(variables, "flowTypeName", factorContext.getFlowTypeName(), "mfa");
            putSafely(variables, "currentState",
                    factorContext.getCurrentState() != null ? factorContext.getCurrentState().name() : MfaState.NONE.name(),
                    MfaState.NONE.name());
            putSafely(variables, "version", factorContext.getVersion(), 0);

            // 선택적 필드
            if (factorContext.getCurrentProcessingFactor() != null) {
                variables.put("currentFactorType", factorContext.getCurrentProcessingFactor().name());
            }

            putSafely(variables, "currentStepId", factorContext.getCurrentStepId(), null);
            putSafely(variables, "retryCount", factorContext.getRetryCount(), 0);
            putSafely(variables, "lastError", factorContext.getLastError(), null);
            putSafely(variables, "mfaRequiredAsPerPolicy", factorContext.isMfaRequiredAsPerPolicy(), false);

            // Authentication 객체
            if (factorContext.getPrimaryAuthentication() != null) {
                variables.put("primaryAuthentication", factorContext.getPrimaryAuthentication());
            } else {
                log.warn("PrimaryAuthentication is null for session: {}", factorContext.getMfaSessionId());
            }

            // ========== 중요: 누락된 데이터 직렬화 추가 ==========

            // 1. completedFactors 직렬화
            if (!factorContext.getCompletedFactors().isEmpty()) {
                String completedFactorsStr = serializeCompletedFactors(factorContext.getCompletedFactors());
                variables.put("completedFactors", completedFactorsStr);
                log.debug("Serialized {} completed factors", factorContext.getCompletedFactors().size());
            }

            // 2. registeredMfaFactors 직렬화
            List<AuthType> registeredFactors = factorContext.getRegisteredMfaFactors();
            if (!registeredFactors.isEmpty()) {
                String registeredFactorsStr = registeredFactors.stream()
                        .map(AuthType::name)
                        .collect(Collectors.joining(","));
                variables.put("registeredMfaFactors", registeredFactorsStr);
            }

            // 3. factorAttemptCounts 직렬화
            Map<AuthType, Integer> attemptCounts = extractAttemptCounts(factorContext);
            if (!attemptCounts.isEmpty()) {
                String attemptCountsStr = serializeAttemptCounts(attemptCounts);
                variables.put("factorAttemptCounts", attemptCountsStr);
            }

            // 4. failedAttempts 직렬화
            Map<String, Integer> failedAttempts = extractFailedAttempts(factorContext);
            if (!failedAttempts.isEmpty()) {
                String failedAttemptsStr = serializeFailedAttempts(failedAttempts);
                variables.put("failedAttempts", failedAttemptsStr);
            }

            // 5. mfaAttemptHistory 직렬화
            if (!factorContext.getMfaAttemptHistory().isEmpty()) {
                String historyStr = serializeMfaAttemptHistory(factorContext.getMfaAttemptHistory());
                variables.put("mfaAttemptHistory", historyStr);
            }

            // 6. 사용자 정의 attributes 직렬화 (가장 중요!)
            Map<String, Object> attributes = factorContext.getAttributes();
            if (attributes != null && !attributes.isEmpty()) {
                attributes.forEach((key, value) -> {
                    String attrKey = "attr_" + key;

                    // 기본 타입은 그대로 저장
                    if (value instanceof String || value instanceof Number || value instanceof Boolean) {
                        variables.put(attrKey, value);
                    }
                    // Date/Instant는 문자열로 변환
                    else if (value instanceof java.util.Date) {
                        variables.put(attrKey, ((java.util.Date) value).getTime());
                    } else if (value instanceof Instant) {
                        variables.put(attrKey, ((Instant) value).toEpochMilli());
                    }
                    // List<AuthType> 처리
                    else if (value instanceof List<?> list) {
                        if (!list.isEmpty() && list.getFirst() instanceof AuthType) {
                            String serialized = ((List<AuthType>) list).stream()
                                    .map(AuthType::name)
                                    .collect(Collectors.joining(","));
                            variables.put(attrKey, serialized);
                        }
                    }

                    log.trace("Serialized attribute: {} = {}", key, value);
                });
                log.debug("Serialized {} attributes", attributes.size());
            }

            // 7. 타임스탬프 정보
            if (factorContext.getLastActivityTimestamp() != null) {
                variables.put("lastActivityTimestamp", factorContext.getLastActivityTimestamp().toEpochMilli());
            }

            // 8. currentFactorOptions 직렬화
            if (factorContext.getCurrentFactorOptions() != null) {
                variables.put("currentFactorOptions", serializeFactorOptions(factorContext.getCurrentFactorOptions()));
            }

            // 메타데이터
            variables.put("_serializedAt", System.currentTimeMillis());
            variables.put("_adapterVersion", "2.3"); // 버전 업데이트
            variables.put("_stateHash", factorContext.calculateStateHash());

            log.debug("Serialized {} variables for session: {} (including {} attributes, {} completed factors)",
                    variables.size(), factorContext.getMfaSessionId(),
                    attributes != null ? attributes.size() : 0,
                    factorContext.getCompletedFactors().size());

        } catch (Exception e) {
            log.error("Unexpected error in toStateMachineVariables", e);
            variables.put("_error", "serialization_error");
            variables.put("_errorMessage", e.getMessage());

            // 최소한의 데이터 보장
            try {
                if (factorContext != null && factorContext.getMfaSessionId() != null) {
                    variables.put("mfaSessionId", factorContext.getMfaSessionId());
                }
            } catch (Exception ex) {
                // 무시
            }
        }

        // 절대 null 반환하지 않음
        return variables;
    }

    /**
     * Null-safe put 메서드
     */
    private void putSafely(Map<Object, Object> map, String key, Object value, Object defaultValue) {
        if (key != null) {
            if (value != null) {
                map.put(key, value);
            } else if (defaultValue != null) {
                map.put(key, defaultValue);
            }
        }
    }

    @Override
    public void updateFactorContext(StateMachine<MfaState, MfaEvent> stateMachine, FactorContext factorContext) {
        ExtendedState extendedState = stateMachine.getExtendedState();
        Map<Object, Object> variables = extendedState.getVariables();

        // 상태 동기화
        if (stateMachine.getState() != null) {
            factorContext.changeState(stateMachine.getState().getId());
        }

        // 변수에서 업데이트
        updateFactorContextFromVariables(factorContext, variables);
    }

    @Override
    public void updateFactorContext(StateContext<MfaState, MfaEvent> stateContext, FactorContext factorContext) {
        Map<Object, Object> variables = stateContext.getExtendedState().getVariables();

        // 상태 동기화
        if (stateContext.getTarget() != null) {
            factorContext.changeState(stateContext.getTarget().getId());
        }

        updateFactorContextFromVariables(factorContext, variables);
    }

    /**
     * State Machine 에서 FactorContext 완전 재구성
     */
    public FactorContext reconstructFromStateMachine(StateMachine<MfaState, MfaEvent> stateMachine) {
        ExtendedState extendedState = stateMachine.getExtendedState();
        Map<Object, Object> variables = extendedState.getVariables();

        // 필수 정보 추출
        String mfaSessionId = (String) variables.get("mfaSessionId");
        if (mfaSessionId == null) {
            throw new IllegalStateException("MFA session ID not found in state machine");
        }

        Authentication authentication = (Authentication) variables.get("primaryAuthentication");
        if (authentication == null) {
            throw new IllegalStateException("Primary authentication not found in state machine");
        }

        MfaState currentState = stateMachine.getState() != null ?
                stateMachine.getState().getId() : MfaState.NONE;

        String flowTypeName = (String) variables.getOrDefault("flowTypeName", "mfa");

        // FactorContext 생성
        FactorContext factorContext = new FactorContext(
                mfaSessionId,
                authentication,
                currentState,
                flowTypeName
        );

        // 추가 정보 복원
        reconstructAdditionalFields(factorContext, variables);

        log.debug("Reconstructed FactorContext from State Machine: sessionId={}, state={}, version={}",
                mfaSessionId, currentState, factorContext.getVersion());

        return factorContext;
    }

    /**
     * 변수 맵에서 FactorContext 업데이트
     */
    private void updateFactorContextFromVariables(FactorContext factorContext, Map<Object, Object> variables) {
        // 버전 정보
        Object version = variables.get("version");
        if (version instanceof Integer) {
            int targetVersion = (Integer) version;
            // 버전 동기화 (AtomicInteger 특성상 직접 설정 불가)
            while (factorContext.getVersion() < targetVersion) {
                factorContext.incrementVersion();
            }
        }

        // 현재 처리 정보
        String currentFactorType = (String) variables.get("currentFactorType");
        if (currentFactorType != null) {
            try {
                factorContext.setCurrentProcessingFactor(AuthType.valueOf(currentFactorType));
            } catch (IllegalArgumentException e) {
                log.warn("Invalid currentFactorType: {}", currentFactorType);
            }
        }

        factorContext.setCurrentStepId((String) variables.get("currentStepId"));

        // 팩터 옵션 복원
        String factorOptionsStr = (String) variables.get("currentFactorOptions");
//        if (factorOptionsStr != null) {
//            factorContext.setCurrentFactorOptions((AuthenticationProcessingOptions) deserializeFactorOptions(factorOptionsStr));
//        }

        // 재시도 및 에러 정보
        Object retryCount = variables.get("retryCount");
        if (retryCount instanceof Integer) {
            factorContext.setRetryCount((Integer) retryCount);
        }

        factorContext.setLastError((String) variables.get("lastError"));

        // MFA 정책 정보
        Object mfaRequired = variables.get("mfaRequiredAsPerPolicy");
        if (mfaRequired instanceof Boolean) {
            factorContext.setMfaRequiredAsPerPolicy((Boolean) mfaRequired);
        }

        // 완료된 팩터들 복원
        restoreCompletedFactors(factorContext, variables);

        // 등록된 MFA 팩터들 복원
        restoreRegisteredMfaFactors(factorContext, variables);

        // 시도 횟수 복원
        restoreAttemptCounts(factorContext, variables);

        // 실패 시도 복원
        restoreFailedAttempts(factorContext, variables);

        // MFA 시도 이력 복원
        restoreMfaAttemptHistory(factorContext, variables);

        // 사용자 정의 속성 복원
        restoreUserAttributes(factorContext, variables);

        // 타임스탬프 복원
        restoreTimestamps(factorContext, variables);
    }

    /**
     * 추가 필드 재구성
     */
    private void reconstructAdditionalFields(FactorContext factorContext, Map<Object, Object> variables) {
        updateFactorContextFromVariables(factorContext, variables);

        // 상태 해시 검증
        String storedHash = (String) variables.get("stateHash");
        String currentHash = factorContext.calculateStateHash();
        if (storedHash != null && !storedHash.equals(currentHash)) {
            log.warn("State hash mismatch for session: {} (stored: {}, current: {})",
                    factorContext.getMfaSessionId(), storedHash, currentHash);
        }
    }

    // === 직렬화 메서드들 ===

    private String serializeFactorOptions(Object factorOptions) {
        // FactorOptions 직렬화 로직
        return factorOptions.toString(); // 실제 구현에서는 JSON 등 사용
    }

    private Object deserializeFactorOptions(String factorOptionsStr) {
        // FactorOptions 역직렬화 로직
        return factorOptionsStr; // 실제 구현에서는 JSON 등 사용
    }

    private String serializeCompletedFactors(List<AuthenticationStepConfig> completedFactors) {
        return completedFactors.stream()
                .map(config -> String.format("%s-%s-%d-%b",
                        config.getStepId(),
                        config.getType(),
                        config.getOrder(),
                        config.isRequired()))
                .collect(Collectors.joining(";"));
    }

    private String serializeAttemptCounts(Map<AuthType, Integer> attemptCounts) {
        return attemptCounts.entrySet().stream()
                .map(entry -> entry.getKey().name() + ":" + entry.getValue())
                .collect(Collectors.joining(","));
    }

    private String serializeFailedAttempts(Map<String, Integer> failedAttempts) {
        return failedAttempts.entrySet().stream()
                .map(entry -> entry.getKey() + ":" + entry.getValue())
                .collect(Collectors.joining(","));
    }

    private String serializeMfaAttemptHistory(List<FactorContext.MfaAttemptDetail> attemptHistory) {
        return attemptHistory.stream()
                .map(detail -> String.format("%s:%b:%d:%s",
                        detail.getFactorType() != null ? detail.getFactorType().name() : "NULL",
                        detail.isSuccess(),
                        detail.getTimestamp().toEpochMilli(),
                        detail.getDetail().replace(":", "\\:")))
                .collect(Collectors.joining(";"));
    }

    // === 복원 메서드들 ===

    private void restoreCompletedFactors(FactorContext factorContext, Map<Object, Object> variables) {
        String completedFactorsStr = (String) variables.get("completedFactors");
        if (completedFactorsStr != null && !completedFactorsStr.isEmpty()) {
            List<AuthenticationStepConfig> configs = Arrays.stream(completedFactorsStr.split(";"))
                    .filter(s -> !s.trim().isEmpty())
                    .map(this::parseAuthenticationStepConfig)
                    .filter(Objects::nonNull)
                    .toList();

//            factorContext.getCompletedFactors().clear();
            configs.forEach(factorContext::addCompletedFactor);
        }
    }

    private void restoreRegisteredMfaFactors(FactorContext factorContext, Map<Object, Object> variables) {
        String registeredFactorsStr = (String) variables.get("registeredMfaFactors");
        if (registeredFactorsStr != null && !registeredFactorsStr.isEmpty()) {
            List<AuthType> factors = Arrays.stream(registeredFactorsStr.split(","))
                    .filter(s -> !s.trim().isEmpty())
                    .map(this::parseAuthTypeSafely)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());

            factorContext.setRegisteredMfaFactors(factors);
        }
    }

    private void restoreAttemptCounts(FactorContext factorContext, Map<Object, Object> variables) {
        String attemptCountsStr = (String) variables.get("factorAttemptCounts");
        if (attemptCountsStr != null && !attemptCountsStr.isEmpty()) {
            Arrays.stream(attemptCountsStr.split(","))
                    .filter(s -> !s.trim().isEmpty())
                    .forEach(entry -> {
                        String[] parts = entry.split(":");
                        if (parts.length == 2) {
                            AuthType factor = parseAuthTypeSafely(parts[0]);
                            if (factor != null) {
                                int count = Integer.parseInt(parts[1]);
                                // factorContext에 시도 횟수 설정
                                for (int i = 0; i < count; i++) {
                                    factorContext.incrementAttemptCount(factor);
                                }
                            }
                        }
                    });
        }
    }

    private void restoreFailedAttempts(FactorContext factorContext, Map<Object, Object> variables) {
        String failedAttemptsStr = (String) variables.get("failedAttempts");
        if (failedAttemptsStr != null && !failedAttemptsStr.isEmpty()) {
            Arrays.stream(failedAttemptsStr.split(","))
                    .filter(s -> !s.trim().isEmpty())
                    .forEach(entry -> {
                        String[] parts = entry.split(":");
                        if (parts.length == 2) {
                            String key = parts[0];
                            int count = Integer.parseInt(parts[1]);
                            // factorContext에 실패 횟수 설정
                            for (int i = 0; i < count; i++) {
                                factorContext.incrementFailedAttempts(key);
                            }
                        }
                    });
        }
    }

    private void restoreMfaAttemptHistory(FactorContext factorContext, Map<Object, Object> variables) {
        String historyStr = (String) variables.get("mfaAttemptHistory");
        if (historyStr != null && !historyStr.isEmpty()) {
            Arrays.stream(historyStr.split(";"))
                    .filter(s -> !s.trim().isEmpty())
                    .forEach(entry -> {
                        String[] parts = entry.split(":");
                        if (parts.length >= 4) {
                            AuthType factorType = "NULL".equals(parts[0]) ? null :
                                    parseAuthTypeSafely(parts[0]);
                            boolean success = Boolean.parseBoolean(parts[1]);
                            String detail = parts[3].replace("\\:", ":");

                            factorContext.recordAttempt(factorType, success, detail);
                        }
                    });
        }
    }

    private void restoreUserAttributes(FactorContext factorContext, Map<Object, Object> variables) {
        variables.entrySet().stream()
                .filter(entry -> entry.getKey().toString().startsWith("attr_"))
                .forEach(entry -> {
                    String key = entry.getKey().toString().substring(5); // "attr_" 제거
                    factorContext.setAttribute(key, entry.getValue());
                });
    }

    private void restoreTimestamps(FactorContext factorContext, Map<Object, Object> variables) {
        Object lastActivityObj = variables.get("lastActivityTimestamp");
        if (lastActivityObj instanceof Long) {
            Instant lastActivity = Instant.ofEpochMilli((Long) lastActivityObj);
            factorContext.setAttribute("lastActivityTimestamp", lastActivity);
        }
    }

    // === 유틸리티 메서드들 ===

    private AuthenticationStepConfig parseAuthenticationStepConfig(String configStr) {
        try {
            String[] parts = configStr.split("-");
            if (parts.length >= 3) {
                AuthenticationStepConfig config = new AuthenticationStepConfig();
                config.setStepId(parts[0]);
                config.setType(parts[1]);
                config.setOrder(Integer.parseInt(parts[2]));
                config.setRequired(parts.length > 3 ? Boolean.parseBoolean(parts[3]) : true);
                return config;
            }
        } catch (Exception e) {
            log.warn("Failed to parse AuthenticationStepConfig: {}", configStr, e);
        }
        return null;
    }

    private AuthType parseAuthTypeSafely(String typeStr) {
        try {
            return AuthType.valueOf(typeStr.toUpperCase());
        } catch (IllegalArgumentException e) {
            log.warn("Invalid AuthType: {}", typeStr);
            return null;
        }
    }

    private Map<AuthType, Integer> extractAttemptCounts(FactorContext factorContext) {
        Map<AuthType, Integer> counts = new HashMap<>();
        for (AuthType factor : AuthType.values()) {
            int count = factorContext.getAttemptCount(factor);
            if (count > 0) {
                counts.put(factor, count);
            }
        }
        return counts;
    }

    /**
     * FactorContext 에서 failedAttempts 추출
     */
    private Map<String, Integer> extractFailedAttempts(FactorContext factorContext) {
        // FactorContext에 추가한 getter 사용
        return factorContext.getFailedAttempts();
    }

}