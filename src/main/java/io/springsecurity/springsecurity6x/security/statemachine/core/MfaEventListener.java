package io.springsecurity.springsecurity6x.security.statemachine.core;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;

/**
 * MFA 이벤트 리스너
 */
@FunctionalInterface
public interface MfaEventListener {
    void onEvent(MfaEvent event, FactorContext context, String sessionId);
}
