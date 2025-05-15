package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;     // 새로운 MfaState 사용
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException; // 가정된 경로

public class RecoveryStateHandler implements MfaStateHandler {

    @Override
    public boolean supports(MfaState state) {
        // 복구 코드 Factor에 대한 챌린지 시작 또는 검증 보류 상태 지원
        return state == MfaState.FACTOR_CHALLENGE_INITIATED || state == MfaState.FACTOR_VERIFICATION_PENDING;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        if (ctx.getCurrentProcessingFactor() != AuthType.RECOVERY_CODE) {
            throw new IllegalStateException("RecoveryStateHandler called for non-RecoveryCode factor: " + ctx.getCurrentProcessingFactor());
        }

        MfaState currentState = ctx.getCurrentState();

        if (currentState == MfaState.FACTOR_CHALLENGE_INITIATED) {
            if (event == MfaEvent.SUBMIT_CREDENTIAL) { // 사용자가 복구 코드를 제출
                ctx.getLastActivityTimestamp();
                return MfaState.FACTOR_VERIFICATION_PENDING;

            } else if (event == MfaEvent.ERROR) { // 복구 코드 입력 UI 로드 실패 등
                return MfaState.AWAITING_MFA_FACTOR_SELECTION;
            }

        } else if (currentState == MfaState.FACTOR_VERIFICATION_PENDING) {
            // 검증 결과는 외부에서 처리
            if (event == MfaEvent.TIMEOUT) {
                return MfaState.MFA_SESSION_INVALIDATED;
            }
        }

        // 이전 코드의 MfaState.RECOVERY 및 MfaEvent.RECOVER 관련 로직은
        // 새로운 MFA 흐름에서는 Recovery Code Factor의 일반적인 처리로 통합됨.
        // 즉, 사용자가 AWAITING_MFA_FACTOR_SELECTION 상태에서 RECOVERY_CODE를 선택하고,
        // FACTOR_SELECTED 이벤트가 발생하여 이 핸들러가 관여하게 됨.

        throw new InvalidTransitionException(currentState, event);
    }
}
