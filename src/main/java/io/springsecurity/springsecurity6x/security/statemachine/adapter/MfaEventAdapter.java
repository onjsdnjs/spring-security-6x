package io.springsecurity.springsecurity6x.security.statemachine.adapter;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import org.springframework.messaging.Message;

/**
 * MFA 이벤트 어댑터 인터페이스
 */
public interface MfaEventAdapter {

    /**
     * 액션 문자열을 MfaEvent로 변환
     */
    MfaEvent determineEvent(String action, FactorContext context);

    /**
     * 특정 이벤트가 현재 컨텍스트에서 발생 가능한지 확인
     */
    boolean canTriggerEvent(MfaEvent event, FactorContext context);

    /**
     * 최대 재시도 횟수 가져오기
     */
    int getMaxRetries();

    /**
     * 세션 지속 시간 계산
     */
    long calculateSessionDuration(FactorContext context);

    /**
     * MfaEvent를 Spring State Machine Message로 변환
     */
    default Message<MfaEvent> toStateMachineMessage(MfaEvent event, FactorContext context) {
        return org.springframework.messaging.support.MessageBuilder
                .withPayload(event)
                .setHeader("mfaSessionId", context.getMfaSessionId())
                .setHeader("timestamp", System.currentTimeMillis())
                .build();
    }
}