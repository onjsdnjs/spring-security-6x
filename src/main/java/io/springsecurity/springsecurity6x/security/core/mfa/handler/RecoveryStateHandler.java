package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;

public class RecoveryStateHandler implements MfaStateHandler {

    @Override
    public boolean supports(MfaState state) {
        // 복구 코드 Factor에 대한 챌린지 시작 또는 검증 보류 상태 지원
        return state == MfaState.FACTOR_CHALLENGE_INITIATED || state == MfaState.FACTOR_VERIFICATION_PENDING;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        if (ctx.getCurrentProcessingFactor() != AuthType.RECOVERY_CODE) {
            // 이 핸들러는 Recovery Code Factor를 위한 것
        }

        MfaState currentState = ctx.getCurrentState();

        if (currentState == MfaState.FACTOR_CHALLENGE_INITIATED && ctx.getCurrentProcessingFactor() == AuthType.RECOVERY_CODE) {
            if (event == MfaEvent.SUBMIT_CREDENTIAL) { // 사용자가 복구 코드를 제출한 경우
                ctx.getLastActivityTimestamp();
                return MfaState.FACTOR_VERIFICATION_PENDING;
            }
        }

        throw new InvalidTransitionException(currentState, event);
    }
}
