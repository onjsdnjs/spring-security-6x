package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;

/**
 * 토큰 발급 단계 상태 전이 핸들러
 */
public class TokenStateHandler implements MfaStateHandler {
    @Override
    public boolean supports(MfaState state) {
        return state == MfaState.PASSKEY_SUBMITTED;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {

        if (event == MfaEvent.ISSUE_TOKEN) {
            return MfaState.TOKEN_ISSUANCE;
        }
        throw new IllegalStateException(
                "Unsupported event " + event + " in state " + ctx.currentState());
    }
}
