package io.springsecurity.springsecurity6x.security.statemachine.core;

import org.springframework.statemachine.StateMachinePersist;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;

/**
 * State Machine 영속성 관리
 * Spring State Machine의 StateMachinePersister를 확장
 */
public interface MfaStateMachinePersister extends
        StateMachinePersist<MfaState, MfaEvent, String> {

    /**
     * State Machine 컨텍스트 저장
     * @param context State Machine 컨텍스트
     * @param id 저장 ID (sessionId)
     */
    @Override
    void write(org.springframework.statemachine.StateMachineContext<MfaState, MfaEvent> context, String id) throws Exception;

    /**
     * State Machine 컨텍스트 조회
     * @param id 조회 ID (sessionId)
     * @return State Machine 컨텍스트
     */
    @Override
    org.springframework.statemachine.StateMachineContext<MfaState, MfaEvent> read(String id) throws Exception;
}