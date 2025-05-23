package io.springsecurity.springsecurity6x.security.statemachine.core;

import org.springframework.statemachine.StateMachine;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;

/**
 * State Machine 인스턴스 생성 팩토리
 */
public interface MfaStateMachineFactory {

    /**
     * 새로운 State Machine 인스턴스 생성
     * @param machineId 머신 ID (일반적으로 sessionId)
     * @return 새로운 State Machine 인스턴스
     */
    StateMachine<MfaState, MfaEvent> createStateMachine(String machineId);

    /**
     * 기존 State Machine 복원
     * @param machineId 머신 ID
     * @param state 복원할 상태
     * @return 복원된 State Machine 인스턴스
     */
    StateMachine<MfaState, MfaEvent> restoreStateMachine(String machineId, MfaState state);
}
