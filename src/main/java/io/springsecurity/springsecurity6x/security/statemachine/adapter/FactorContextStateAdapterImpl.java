package io.springsecurity.springsecurity6x.security.statemachine.adapter;

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

    @Override
    public Map<Object, Object> toStateMachineVariables(FactorContext factorContext) {
        Map<Object, Object> variables = new HashMap<>();

        // 핵심 필드만 직렬화
        variables.put("mfaSessionId", factorContext.getMfaSessionId());
        variables.put("username", factorContext.getUsername());
        variables.put("flowTypeName", factorContext.getFlowTypeName());
        variables.put("currentState", factorContext.getCurrentState().name());
        variables.put("version", factorContext.getVersion());

        // 현재 처리 정보 (필수)
        if (factorContext.getCurrentProcessingFactor() != null) {
            variables.put("currentFactorType", factorContext.getCurrentProcessingFactor().name());
        }
        variables.put("currentStepId", factorContext.getCurrentStepId());

        // 재시도 정보 (필수)
        variables.put("retryCount", factorContext.getRetryCount());
        variables.put("lastError", factorContext.getLastError());

        // MFA 정책 정보 (필수)
        variables.put("mfaRequiredAsPerPolicy", factorContext.isMfaRequiredAsPerPolicy());

        // 복잡한 객체는 레퍼런스만 저장
        variables.put("primaryAuthentication", factorContext.getPrimaryAuthentication());

        // 메타데이터 최소화
        variables.put("_serializedAt", System.currentTimeMillis());
        variables.put("_adapterVersion", "2.1");

        log.debug("Serialized essential FactorContext data ({} variables) for session: {}",
                variables.size(), factorContext.getMfaSessionId());

        return variables;
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
        if (factorOptionsStr != null) {
            factorContext.setCurrentFactorOptions((AuthenticationProcessingOptions) deserializeFactorOptions(factorOptionsStr));
        }

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
                .map(config -> String.format("%s:%s:%d:%b",
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
                    .collect(Collectors.toList());

            factorContext.getCompletedFactors().clear();
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
            String[] parts = configStr.split(":");
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

    private Map<String, Integer> extractFailedAttempts(FactorContext factorContext) {
        // FactorContext에서 실패 시도 정보 추출
        // 실제 구현에서는 factorContext의 내부 필드에 접근
        return new HashMap<>(); // 임시 구현
    }

    private boolean isSerializableAttribute(String key, Object value) {
        if (value == null) return false;

        // 기본 타입과 문자열만 허용
        return value instanceof String ||
                value instanceof Number ||
                value instanceof Boolean ||
                value instanceof java.util.Date ||
                value instanceof Instant;
    }
}