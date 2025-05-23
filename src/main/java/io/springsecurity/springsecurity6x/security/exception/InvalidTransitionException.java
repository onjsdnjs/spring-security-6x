package io.springsecurity.springsecurity6x.security.exception;

import io.springsecurity.springsecurity6x.security.statemachine.config.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaState;

/**
 * FSM 전이 불가 시 던져지는 예외
 */
public class InvalidTransitionException extends RuntimeException {
    private final MfaState state;
    private final MfaEvent event;

    public InvalidTransitionException(MfaState state, MfaEvent event) {
        super(String.format("Cannot transition from %s on event %s", state, event));
        this.state = state;
        this.event = event;
    }

    public MfaState getState() {
        return state;
    }

    public MfaEvent getEvent() {
        return event;
    }
}

