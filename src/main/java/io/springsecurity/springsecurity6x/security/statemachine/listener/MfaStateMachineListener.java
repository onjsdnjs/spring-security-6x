package io.springsecurity.springsecurity6x.security.statemachine.listener;

import org.springframework.statemachine.listener.StateMachineListener;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;

/**
 * MFA State Machine 이벤트 리스너
 */
public interface MfaStateMachineListener extends StateMachineListener<MfaState, MfaEvent> {

    /**
     * 상태 전이 성공 시 호출
     * @param from 이전 상태
     * @param to 새로운 상태
     * @param event 트리거 이벤트
     */
    default void onSuccessfulTransition(MfaState from, MfaState to, MfaEvent event) {
        // 기본 구현 제공 가능
    }

    /**
     * 상태 전이 실패 시 호출
     * @param from 현재 상태
     * @param event 시도된 이벤트
     * @param reason 실패 이유
     */
    default void onFailedTransition(MfaState from, MfaEvent event, String reason) {
        // 기본 구현 제공 가능
    }
}