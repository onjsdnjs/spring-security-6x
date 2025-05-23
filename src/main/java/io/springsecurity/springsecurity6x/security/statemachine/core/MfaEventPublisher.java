package io.springsecurity.springsecurity6x.security.statemachine.core;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;

/**
 * MFA 이벤트 발행 인터페이스
 * State Machine과 기존 시스템 간의 이벤트 브릿지
 */
public interface MfaEventPublisher {

    /**
     * MFA 이벤트 발행
     * @param event 발행할 이벤트
     * @param context 이벤트 컨텍스트
     * @param sessionId MFA 세션 ID
     */
    void publishEvent(MfaEvent event, FactorContext context, String sessionId);

    /**
     * 이벤트 리스너 등록
     * @param eventType 구독할 이벤트 타입
     * @param listener 이벤트 리스너
     */
    void subscribe(MfaEvent eventType, MfaEventListener listener);

    /**
     * 이벤트 리스너 해제
     * @param eventType 구독 해제할 이벤트 타입
     * @param listener 이벤트 리스너
     */
    void unsubscribe(MfaEvent eventType, MfaEventListener listener);
}
