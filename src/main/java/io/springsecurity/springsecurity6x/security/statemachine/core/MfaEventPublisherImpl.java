package io.springsecurity.springsecurity6x.security.statemachine.core;

import io.springsecurity.springsecurity6x.security.statemachine.config.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * MFA 이벤트 발행 구현체
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MfaEventPublisherImpl implements MfaEventPublisher {

    private final ApplicationEventPublisher applicationEventPublisher;

    @Override
    public void publishStateChange(String sessionId, MfaState state, MfaEvent event) {
        log.debug("Publishing state change event - Session: {}, State: {}, Event: {}",
                sessionId, state, event);

        MfaStateChangeEvent stateChangeEvent = new MfaStateChangeEvent(
                this,
                sessionId,
                state,
                event,
                LocalDateTime.now()
        );

        applicationEventPublisher.publishEvent(stateChangeEvent);
    }

    @Override
    public void publishError(String sessionId, Exception error) {
        log.error("Publishing error event - Session: {}, Error: {}",
                sessionId, error.getMessage());

        MfaErrorEvent errorEvent = new MfaErrorEvent(
                this,
                sessionId,
                error,
                LocalDateTime.now()
        );

        applicationEventPublisher.publishEvent(errorEvent);
    }

    @Override
    public void publishCustomEvent(String eventType, Object payload) {
        log.debug("Publishing custom event - Type: {}", eventType);

        Map<String, Object> eventData = new HashMap<>();
        eventData.put("eventType", eventType);
        eventData.put("payload", payload);
        eventData.put("timestamp", LocalDateTime.now());

        applicationEventPublisher.publishEvent(eventData);
    }

    /**
     * MFA 상태 변경 이벤트
     */
    public static class MfaStateChangeEvent {
        private final Object source;
        private final String sessionId;
        private final MfaState state;
        private final MfaEvent event;
        private final LocalDateTime timestamp;

        public MfaStateChangeEvent(Object source, String sessionId,
                                   MfaState state, MfaEvent event,
                                   LocalDateTime timestamp) {
            this.source = source;
            this.sessionId = sessionId;
            this.state = state;
            this.event = event;
            this.timestamp = timestamp;
        }

        // Getters
        public Object getSource() { return source; }
        public String getSessionId() { return sessionId; }
        public MfaState getState() { return state; }
        public MfaEvent getEvent() { return event; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    /**
     * MFA 에러 이벤트
     */
    public static class MfaErrorEvent {
        private final Object source;
        private final String sessionId;
        private final Exception error;
        private final LocalDateTime timestamp;

        public MfaErrorEvent(Object source, String sessionId,
                             Exception error, LocalDateTime timestamp) {
            this.source = source;
            this.sessionId = sessionId;
            this.error = error;
            this.timestamp = timestamp;
        }

        // Getters
        public Object getSource() { return source; }
        public String getSessionId() { return sessionId; }
        public Exception getError() { return error; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}