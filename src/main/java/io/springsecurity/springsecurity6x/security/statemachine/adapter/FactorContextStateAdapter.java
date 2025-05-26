package io.springsecurity.springsecurity6x.security.statemachine.adapter;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.StateContext;

import java.util.Map;

/**
 * FactorContext와 State Machine 간의 데이터 변환 어댑터
 */
public interface FactorContextStateAdapter {

    /**
     * FactorContext를 State Machine 변수로 변환
     */
    Map<Object, Object> toStateMachineVariables(FactorContext factorContext);

    /**
     * State Machine에서 FactorContext 업데이트
     */
    void updateFactorContext(StateMachine<MfaState, MfaEvent> stateMachine, FactorContext factorContext);

    /**
     * StateContext에서 FactorContext 업데이트
     */
    void updateFactorContext(StateContext<MfaState, MfaEvent> stateContext, FactorContext factorContext);

    FactorContext reconstructFromStateMachine(StateMachine<MfaState, MfaEvent> stateMachine);

}