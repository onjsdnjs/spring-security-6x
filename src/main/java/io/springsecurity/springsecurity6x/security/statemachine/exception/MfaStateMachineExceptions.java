package io.springsecurity.springsecurity6x.security.statemachine.exception;

/**
 * MFA 상태 머신 관련 비즈니스 예외
 */
public class MfaStateMachineExceptions {

    public static class InvalidFactorException extends RuntimeException {
        public InvalidFactorException(String message) {
            super(message);
        }
    }

    public static class ChallengeGenerationException extends RuntimeException {
        public ChallengeGenerationException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class FactorVerificationException extends RuntimeException {
        public FactorVerificationException(String message) {
            super(message);
        }
    }

    public static class StateTransitionException extends RuntimeException {
        public StateTransitionException(String message) {
            super(message);
        }
    }

    public static class SessionExpiredException extends RuntimeException {
        public SessionExpiredException(String message) {
            super(message);
        }
    }

    public static class ConcurrencyException extends RuntimeException {
        public ConcurrencyException(String message) {
            super(message);
        }
    }
}