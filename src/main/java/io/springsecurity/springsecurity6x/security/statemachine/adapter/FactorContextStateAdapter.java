package io.springsecurity.springsecurity6x.security.statemachine.adapter;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import org.springframework.statemachine.StateContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;

/**
 * FactorContext와 State Machine 간의 상태 동기화 어댑터
 */
public interface FactorContextStateAdapter {

    /**
     * FactorContext를 State Machine 컨텍스트로 변환
     * @param factorContext Factor 컨텍스트
     * @return State Machine 확장 상태 변수 맵
     */
    java.util.Map<Object, Object> toStateMachineVariables(FactorContext factorContext);

    /**
     * State Machine 컨텍스트를 FactorContext로 업데이트
     * @param stateContext State Machine 컨텍스트
     * @param factorContext 업데이트할 Factor 컨텍스트
     */
    void updateFactorContext(StateContext<MfaState, MfaEvent> stateContext, FactorContext factorContext);

    /**
     * StateMachineContext를 FactorContext로 업데이트 (오버로드)
     * @param stateMachineContext State Machine 컨텍스트
     * @param factorContext 업데이트할 Factor 컨텍스트
     */
    void updateFactorContext(org.springframework.statemachine.StateMachineContext<MfaState, MfaEvent> stateMachineContext, FactorContext factorContext);

    /**
     * State Machine 상태를 MfaState로 매핑
     * @param state State Machine의 현재 상태
     * @return 매핑된 MfaState
     */
    MfaState mapToMfaState(org.springframework.statemachine.state.State<MfaState, MfaEvent> state);
}
