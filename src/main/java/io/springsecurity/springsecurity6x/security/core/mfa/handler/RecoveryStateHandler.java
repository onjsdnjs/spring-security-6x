package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;

/**
 * 복구 상태 전이 핸들러
 */
public class RecoveryStateHandler implements MfaStateHandler {
    @Override
    public boolean supports(MfaState state) {
        return state == MfaState.RECOVERY;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        // RECOVERY 상태에서 RECOVER 이벤트 수신 시 FORM_CHALLENGE로 전이
        if (event == MfaEvent.RECOVER) {
            return MfaState.FORM_CHALLENGE;
        }
        throw new IllegalStateException(
                "Unsupported event " + event + " in state " + ctx.currentState());
    }
}
