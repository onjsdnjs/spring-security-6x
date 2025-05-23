package io.springsecurity.springsecurity6x.security.statemachine.core;

import io.springsecurity.springsecurity6x.security.statemachine.config.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaState;
import org.springframework.statemachine.StateMachine;

/**
 * MFA State Machine 팩토리 인터페이스
 */
public interface MfaStateMachineFactory {

    /**
     * 새로운 상태 머신 생성
     */
    StateMachine<MfaState, MfaEvent> createStateMachine(String machineId);

    /**
     * 랜덤 ID로 새 상태 머신 생성
     */
    StateMachine<MfaState, MfaEvent> createStateMachine();

    /**
     * 저장된 상태 머신 복원
     */
    StateMachine<MfaState, MfaEvent> restoreStateMachine(String machineId);

    /**
     * 상태 머신 해제
     */
    void releaseStateMachine(String machineId);
}