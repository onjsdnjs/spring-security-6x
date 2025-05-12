package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;

public interface MfaStateHandler {
    boolean supports(MfaState state);
    MfaState handleEvent(MfaEvent event, FactorContext ctx);
}
