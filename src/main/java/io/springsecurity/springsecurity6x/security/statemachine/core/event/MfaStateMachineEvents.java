package io.springsecurity.springsecurity6x.security.statemachine.core.event;

import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.Builder;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.time.Duration;
import java.time.LocalDateTime;

/**
 * MFA State Machine 이벤트 정의
 */
public class MfaStateMachineEvents {

    /**
     * 상태 변경 이벤트
     */
    @Getter
    public static class StateChangeEvent extends ApplicationEvent {
        private final String sessionId;
        private final MfaState fromState;
        private final MfaState toState;
        private final MfaEvent event;
        private final LocalDateTime timestamp;
        private final Duration duration;

        public StateChangeEvent(Object source, String sessionId,
                                MfaState fromState, MfaState toState,
                                MfaEvent event, Duration duration) {
            super(source);
            this.sessionId = sessionId;
            this.fromState = fromState;
            this.toState = toState;
            this.event = event;
            this.timestamp = LocalDateTime.now();
            this.duration = duration;
        }

        public String getTransitionKey() {
            return fromState + "_to_" + toState;
        }
    }

    /**
     * 에러 이벤트
     */
    @Getter
    public static class ErrorEvent extends ApplicationEvent {
        private final String sessionId;
        private final MfaState currentState;
        private final MfaEvent event;
        private final Exception error;
        private final LocalDateTime timestamp;
        private final ErrorType errorType;

        public ErrorEvent(Object source, String sessionId,
                          MfaState currentState, MfaEvent event,
                          Exception error) {
            super(source);
            this.sessionId = sessionId;
            this.currentState = currentState;
            this.event = event;
            this.error = error;
            this.timestamp = LocalDateTime.now();
            this.errorType = categorizeError(error);
        }

        private ErrorType categorizeError(Exception error) {
            if (error instanceof SecurityException) return ErrorType.SECURITY;
            if (error.getMessage() != null) {
                if (error.getMessage().contains("timeout")) return ErrorType.TIMEOUT;
                if (error.getMessage().contains("limit")) return ErrorType.LIMIT_EXCEEDED;
            }
            return ErrorType.SYSTEM;
        }

        public enum ErrorType {
            SECURITY, TIMEOUT, LIMIT_EXCEEDED, SYSTEM
        }
    }

    /**
     * 성능 경고 이벤트
     */
    @Getter
    public static class PerformanceAlertEvent extends ApplicationEvent {
        private final AlertType alertType;
        private final String description;
        private final double threshold;
        private final double actualValue;
        private final Severity severity;
        private final LocalDateTime timestamp;

        public PerformanceAlertEvent(Object source, AlertType alertType,
                                     String description, double threshold,
                                     double actualValue, Severity severity) {
            super(source);
            this.alertType = alertType;
            this.description = description;
            this.threshold = threshold;
            this.actualValue = actualValue;
            this.severity = severity;
            this.timestamp = LocalDateTime.now();
        }

        public enum AlertType {
            SLOW_TRANSITION, HIGH_ERROR_RATE, POOL_EXHAUSTION,
            CIRCUIT_BREAKER_OPEN, MEMORY_PRESSURE
        }

        public enum Severity {
            LOW, MEDIUM, HIGH, CRITICAL
        }
    }

    /**
     * 커스텀 이벤트
     */
    @Getter
    public static class CustomEvent extends ApplicationEvent {
        private final String eventType;
        private final Object payload;
        private final LocalDateTime timestamp;

        public CustomEvent(Object source, String eventType, Object payload) {
            super(source);
            this.eventType = eventType;
            this.payload = payload;
            this.timestamp = LocalDateTime.now();
        }
    }
}