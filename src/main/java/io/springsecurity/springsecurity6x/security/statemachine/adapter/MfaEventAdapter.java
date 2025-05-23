package io.springsecurity.springsecurity6x.security.statemachine.adapter;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;

/**
 * MfaEvent와 State Machine Event 간의 변환 어댑터
 */
public interface MfaEventAdapter {

    /**
     * MfaEvent를 State Machine 메시지로 변환
     * @param event MFA 이벤트
     * @param context Factor 컨텍스트
     * @return State Machine 메시지
     */
    org.springframework.messaging.Message<MfaEvent> toStateMachineMessage(MfaEvent event, FactorContext context);

    /**
     * State Machine 이벤트에서 MfaEvent 추출
     * @param message State Machine 메시지
     * @return MFA 이벤트
     */
    MfaEvent extractMfaEvent(org.springframework.messaging.Message<?> message);
}