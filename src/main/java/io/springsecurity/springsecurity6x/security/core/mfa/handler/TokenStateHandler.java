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
        return switch (state) {
            case FORM_SUBMITTED, REST_SUBMITTED, OTT_SUBMITTED, PASSKEY_SUBMITTED -> true;
            default -> false;
        };
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        if (event == MfaEvent.SUBMIT_CREDENTIAL || event == MfaEvent.ISSUE_TOKEN) {
            return MfaState.TOKEN_ISSUANCE;
        }
        throw new IllegalStateException(
                "Unsupported event " + event + " in state " + ctx.currentState());
    }
}

