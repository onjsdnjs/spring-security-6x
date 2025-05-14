package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState; // 새로운 MfaState 사용
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException; // 가정된 경로

public class TokenStateHandler implements MfaStateHandler {

    @Override
    public boolean supports(MfaState state) {
        // 모든 MFA 검증이 완료된 상태를 지원
        return state == MfaState.MFA_VERIFICATION_COMPLETED;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        if (ctx.getCurrentState() == MfaState.MFA_VERIFICATION_COMPLETED) {
            if (event == MfaEvent.ISSUE_TOKEN) { // 토큰 발급 요청 이벤트
                // 실제 토큰 발급은 TokenIssuingSuccessHandler 등에서 처리.
                // 여기서는 최종 완료 상태로 전이.
                ctx.getLastActivityTimestamp();
                return MfaState.MFA_FULLY_COMPLETED;
            }
        }
        throw new InvalidTransitionException(ctx.getCurrentState(), event);
    }
}

