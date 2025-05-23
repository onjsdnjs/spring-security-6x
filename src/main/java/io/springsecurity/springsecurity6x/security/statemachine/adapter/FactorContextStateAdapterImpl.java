package io.springsecurity.springsecurity6x.security.statemachine.adapter;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.state.State;
import org.springframework.statemachine.support.DefaultExtendedState;
import org.springframework.statemachine.support.DefaultStateMachineContext;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * FactorContext와 State Machine 간의 상태 동기화 어댑터 구현체
 */
@Slf4j
@Component
public class FactorContextStateAdapterImpl implements FactorContextStateAdapter {

    // State Machine 변수 키 상수
    private static final String VAR_USERNAME = "username";
    private static final String VAR_SESSION_ID = "mfaSessionId";
    private static final String VAR_FLOW_TYPE = "flowTypeName";
    private static final String VAR_CURRENT_FACTOR = "currentProcessingFactor";
    private static final String VAR_CURRENT_STEP_ID = "currentStepId";
    private static final String VAR_RETRY_COUNT = "retryCount";
    private static final String VAR_MFA_REQUIRED = "mfaRequiredAsPerPolicy";
    private static final String VAR_COMPLETED_FACTORS = "completedFactors";
    private static final String VAR_AVAILABLE_FACTORS = "availableFactors";
    private static final String VAR_LAST_ERROR = "lastError";

    @Override
    public Map<Object, Object> toStateMachineVariables(FactorContext factorContext) {
        log.debug("Converting FactorContext to State Machine variables for session: {}",
                factorContext.getMfaSessionId());

        Map<Object, Object> variables = new HashMap<>();

        // 기본 정보
        variables.put(VAR_USERNAME, factorContext.getUsername());
        variables.put(VAR_SESSION_ID, factorContext.getMfaSessionId());
        variables.put(VAR_FLOW_TYPE, factorContext.getFlowTypeName());

        // 현재 처리 상태
        if (factorContext.getCurrentProcessingFactor() != null) {
            variables.put(VAR_CURRENT_FACTOR, factorContext.getCurrentProcessingFactor().name());
        }
        variables.put(VAR_CURRENT_STEP_ID, factorContext.getCurrentStepId());

        // 재시도 정보
        variables.put(VAR_RETRY_COUNT, factorContext.getRetryCount());

        // MFA 정책 정보
        variables.put(VAR_MFA_REQUIRED, factorContext.isMfaRequiredAsPerPolicy());

        // 완료된 팩터들 (List<AuthenticationStepConfig>를 문자열로 변환)
        if (factorContext.getCompletedFactors() != null && !factorContext.getCompletedFactors().isEmpty()) {
            String completedFactorsStr = factorContext.getCompletedFactors().stream()
                    .map(step -> step.getStepId() + ":" + step.getType() + ":" + step.getOrder())
                    .collect(Collectors.joining(","));
            variables.put(VAR_COMPLETED_FACTORS, completedFactorsStr);
        }

        // 사용 가능한 팩터들
        if (factorContext.getAvailableFactors() != null && !factorContext.getAvailableFactors().isEmpty()) {
            variables.put(VAR_AVAILABLE_FACTORS,
                    String.join(",", factorContext.getAvailableFactors().stream()
                            .map(Enum::name)
                            .toList()));
        }

        // 에러 정보
        if (factorContext.getLastError() != null) {
            variables.put(VAR_LAST_ERROR, factorContext.getLastError());
        }

        log.debug("Converted {} variables from FactorContext", variables.size());
        return variables;
    }

    @Override
    public void updateFactorContext(StateContext<MfaState, MfaEvent> stateContext, FactorContext factorContext) {
        log.debug("Updating FactorContext from State Machine context for session: {}",
                factorContext.getMfaSessionId());

        Map<Object, Object> variables = stateContext.getExtendedState().getVariables();

        // 현재 상태 업데이트
        MfaState currentState = stateContext.getSource().getId();
        factorContext.changeState(currentState);

        // 재시도 카운트 업데이트
        Integer retryCount = (Integer) variables.get(VAR_RETRY_COUNT);
        if (retryCount != null) {
            factorContext.setRetryCount(retryCount);
        }

        // 현재 스텝 ID 업데이트
        String currentStepId = (String) variables.get(VAR_CURRENT_STEP_ID);
        if (currentStepId != null) {
            factorContext.setCurrentStepId(currentStepId);
        }

        // 에러 정보 업데이트
        String lastError = (String) variables.get(VAR_LAST_ERROR);
        if (lastError != null) {
            factorContext.setLastError(lastError);
        }

        log.debug("FactorContext updated with state: {}", currentState);
    }

    @Override
    public void updateFactorContext(StateMachineContext<MfaState, MfaEvent> stateMachineContext,
                                    FactorContext factorContext) {
        log.debug("Updating FactorContext from StateMachineContext for session: {}",
                factorContext.getMfaSessionId());

        // StateMachineContext에서 현재 상태 업데이트
        MfaState currentState = stateMachineContext.getState();
        factorContext.changeState(currentState);

        // ExtendedState에서 변수들 업데이트
        Map<Object, Object> variables = stateMachineContext.getExtendedState() != null ?
                stateMachineContext.getExtendedState().getVariables() : new HashMap<>();

        // 재시도 카운트 업데이트
        Integer retryCount = (Integer) variables.get(VAR_RETRY_COUNT);
        if (retryCount != null) {
            factorContext.setRetryCount(retryCount);
        }

        // 현재 스텝 ID 업데이트
        String currentStepId = (String) variables.get(VAR_CURRENT_STEP_ID);
        if (currentStepId != null) {
            factorContext.setCurrentStepId(currentStepId);
        }

        // 에러 정보 업데이트
        String lastError = (String) variables.get(VAR_LAST_ERROR);
        if (lastError != null) {
            factorContext.setLastError(lastError);
        }

        log.debug("FactorContext updated with state: {} from StateMachineContext", currentState);
    }

    @Override
    public MfaState mapToMfaState(State<MfaState, MfaEvent> state) {
        return state != null ? state.getId() : MfaState.NONE;
    }
}