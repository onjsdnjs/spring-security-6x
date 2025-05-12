package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class PasskeyStateHandler implements MfaStateHandler {

    @Override public boolean supports(MfaState state) {
        return state == MfaState.PASSKEY_CHALLENGE;
    }
    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        if (event == MfaEvent.SUBMIT_CREDENTIAL) return MfaState.PASSKEY_SUBMITTED;
        throw new InvalidTransitionException(ctx.getCurrentState(), event);
    }
}
