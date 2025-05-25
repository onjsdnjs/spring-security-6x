package io.springsecurity.springsecurity6x.security.statemachine.core.event;

import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.time.Duration;
import java.time.LocalDateTime;

/**
 * MFA State Machine 관련 이벤트 정의
 */
public class MfaStateMachineEvents {

    @Getter
    @Builder
    @AllArgsConstructor
    public static class MfaStateChangeEvent {
        private final Object source;
        private final String sessionId;
        private final MfaState fromState;
        private final MfaState toState;
        private final MfaEvent event;
        private final LocalDateTime timestamp;
        private final Duration duration;  // MfaStateMachineMonitoring에서 사용

        // 기존 생성자와의 호환성을 위한 추가 생성자
        public MfaStateChangeEvent(Object source, String sessionId,
                                   MfaState state, MfaEvent event,
                                   LocalDateTime timestamp) {
            this(source, sessionId, null, state, event, timestamp, null);
        }
    }

    @Getter
    @Builder
    @AllArgsConstructor
    public static class MfaErrorEvent {
        private final Object source;
        private final String sessionId;
        private final MfaEvent event;  // MfaEventFailureEvent에서 필요
        private final Exception error;
        private final LocalDateTime timestamp;

        // 기존 생성자와의 호환성
        public MfaErrorEvent(Object source, String sessionId,
                             Exception error, LocalDateTime timestamp) {
            this(source, sessionId, null, error, timestamp);
        }
    }

    @Getter
    @Builder
    @AllArgsConstructor
    public static class MfaCustomEvent {
        private final String eventType;
        private final Object payload;
        private final LocalDateTime timestamp;
    }
}
