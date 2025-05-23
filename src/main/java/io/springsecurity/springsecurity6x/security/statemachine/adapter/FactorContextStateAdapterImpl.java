package io.springsecurity.springsecurity6x.security.statemachine.adapter;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * FactorContext와 State Machine 간의 데이터 변환 어댑터 구현체
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class FactorContextStateAdapterImpl implements FactorContextStateAdapter {

    @Override
    public Map<Object, Object> toStateMachineVariables(FactorContext factorContext) {
        Map<Object, Object> variables = new HashMap<>();

        // 기본 정보
        variables.put("mfaSessionId", factorContext.getMfaSessionId());
        variables.put("username", factorContext.getUsername());
        variables.put("currentState", factorContext.getCurrentState());
        variables.put("flowTypeName", factorContext.getFlowTypeName());

        // 현재 처리 중인 팩터 정보
        variables.put("currentStepId", factorContext.getCurrentStepId());
        if (factorContext.getCurrentProcessingFactor() != null) {
            variables.put("currentFactorType", factorContext.getCurrentProcessingFactor().name());
        }

        // 재시도 및 에러 정보
        variables.put("retryCount", factorContext.getRetryCount());
        variables.put("lastError", factorContext.getLastError());

        // 타임스탬프
        variables.put("createdAt", factorContext.getCreatedAt());

        // Authentication 정보
        if (factorContext.getPrimaryAuthentication() != null) {
            variables.put("principalName", factorContext.getPrimaryAuthentication().getName());
            variables.put("primaryAuthentication", factorContext.getPrimaryAuthentication());
        }

        // 완료된 팩터들
        if (!factorContext.getCompletedFactors().isEmpty()) {
            variables.put("completedFactors", serializeCompletedFactors(factorContext));
        }

        // 사용 가능한 팩터들 (attributes에서 가져오기)
        Object availableFactors = factorContext.getAttribute("availableFactors");
        if (availableFactors instanceof Set) {
            variables.put("availableFactors", serializeAvailableFactors((Set<?>) availableFactors));
        }

        // MFA 정책 정보
        variables.put("mfaRequiredAsPerPolicy", factorContext.isMfaRequiredAsPerPolicy());

        return variables;
    }

    @Override
    public void updateFactorContext(StateMachine<MfaState, MfaEvent> stateMachine,
                                    FactorContext factorContext) {
        ExtendedState extendedState = stateMachine.getExtendedState();
        Map<Object, Object> variables = extendedState.getVariables();

        updateFactorContextFromVariables(factorContext, variables);

        // 현재 상태 동기화
        if (stateMachine.getState() != null) {
            factorContext.changeState(stateMachine.getState().getId());
        }
    }

    @Override
    public void updateFactorContext(StateContext<MfaState, MfaEvent> stateContext,
                                    FactorContext factorContext) {
        Map<Object, Object> variables = stateContext.getExtendedState().getVariables();

        updateFactorContextFromVariables(factorContext, variables);

        // 현재 상태 동기화
        if (stateContext.getTarget() != null) {
            factorContext.changeState(stateContext.getTarget().getId());
        }
    }

    /**
     * 변수 맵에서 FactorContext 업데이트
     */
    private void updateFactorContextFromVariables(FactorContext factorContext,
                                                  Map<Object, Object> variables) {
        // 현재 단계 정보
        Object currentStepId = variables.get("currentStepId");
        if (currentStepId instanceof String) {
            factorContext.setCurrentStepId((String) currentStepId);
        }

        // 현재 팩터 타입
        Object currentFactorType = variables.get("currentFactorType");
        if (currentFactorType instanceof String) {
            try {
                factorContext.setCurrentProcessingFactor(AuthType.valueOf((String) currentFactorType));
            } catch (IllegalArgumentException e) {
                log.warn("Invalid currentFactorType: {}", currentFactorType);
            }
        }

        // 재시도 횟수
        Object retryCount = variables.get("retryCount");
        if (retryCount instanceof Integer) {
            factorContext.setRetryCount((Integer) retryCount);
        }

        // 에러 메시지
        Object lastError = variables.get("lastError");
        if (lastError instanceof String) {
            factorContext.setLastError((String) lastError);
        }

        // 추가 속성들
        variables.entrySet().stream()
                .filter(entry -> entry.getKey().toString().startsWith("attr_"))
                .forEach(entry -> {
                    String key = entry.getKey().toString().substring(5); // "attr_" 제거
                    factorContext.setAttribute(key, entry.getValue());
                });
    }

    /**
     * 완료된 팩터 직렬화
     */
    private String serializeCompletedFactors(FactorContext factorContext) {
        return factorContext.getCompletedFactors().stream()
                .map(config -> String.format("%s:%s:%d",
                        config.getStepId(),
                        config.getType(),
                        config.getOrder()))
                .collect(Collectors.joining(","));
    }

    /**
     * 사용 가능한 팩터 직렬화
     */
    private String serializeAvailableFactors(Set<?> availableFactors) {
        return availableFactors.stream()
                .map(Object::toString)
                .collect(Collectors.joining(","));
    }
}