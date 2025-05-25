package io.springsecurity.springsecurity6x.security.statemachine.core.event;

import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;

/**
 * MFA 이벤트 발행 인터페이스
 */
public interface MfaEventPublisher {

    /**
     * 상태 변경 이벤트 발행
     */
    void publishStateChange(String sessionId, MfaState state, MfaEvent event);

    /**
     * 에러 이벤트 발행
     */
    void publishError(String sessionId, Exception error);

    /**
     * 커스텀 이벤트 발행
     */
    void publishCustomEvent(String eventType, Object payload);
}