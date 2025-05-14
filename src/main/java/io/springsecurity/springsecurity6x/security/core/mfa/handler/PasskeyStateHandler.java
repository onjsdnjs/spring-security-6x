package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;

public class PasskeyStateHandler implements MfaStateHandler {

    @Override
    public boolean supports(MfaState state) {
        // Passkey Factor에 대한 챌린지 시작 또는 검증 보류 상태 지원
        return state == MfaState.FACTOR_CHALLENGE_INITIATED ||
                state == MfaState.FACTOR_VERIFICATION_PENDING ||
                state == MfaState.AUTO_ATTEMPT_FACTOR_PENDING || // Passkey 자동 시도 관련 상태 추가
                state == MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        // 현재 처리 중인 Factor가 Passkey인지 확인 (supports에서 더 명확히 하거나 여기서 방어)
        if (ctx.getCurrentProcessingFactor() != AuthType.PASSKEY &&
                !(ctx.getCurrentState() == MfaState.AUTO_ATTEMPT_FACTOR_PENDING && ctx.getPreferredAutoAttemptFactor() == AuthType.PASSKEY) &&
                !(ctx.getCurrentState() == MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING && ctx.getPreferredAutoAttemptFactor() == AuthType.PASSKEY)
        ) {
            // 이 핸들러는 Passkey Factor를 위한 것
        }

        MfaState currentState = ctx.getCurrentState();

        // Passkey 자동 시도 단계
        if (currentState == MfaState.AUTO_ATTEMPT_FACTOR_PENDING && ctx.getPreferredAutoAttemptFactor() == AuthType.PASSKEY) {
            if (event == MfaEvent.REQUEST_CHALLENGE) { // (내부적으로) Passkey Conditional UI 챌린지 요청
                ctx.getLastActivityTimestamp();
                // 챌린지 생성은 외부에서, 여기서는 상태만 변경하여 챌린지 데이터가 FactorContext에 로드될 것을 기대
                return MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING;
            } else if (event == MfaEvent.SUBMIT_CREDENTIAL) { // 사용자가 Conditional UI에서 Passkey 선택 및 응답 제출
                ctx.getLastActivityTimestamp();
                return MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING; // 검증 대기
            }
        }

        // 사용자가 명시적으로 Passkey를 선택한 후의 단계
        if (currentState == MfaState.FACTOR_CHALLENGE_INITIATED && ctx.getCurrentProcessingFactor() == AuthType.PASSKEY) {
            if (event == MfaEvent.SUBMIT_CREDENTIAL) { // Passkey Assertion 제출
                ctx.getLastActivityTimestamp();
                return MfaState.FACTOR_VERIFICATION_PENDING;
            }
        }

        // AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING 또는 FACTOR_VERIFICATION_PENDING 상태에서의 이벤트 처리는
        // 주로 MfaContinuationHandler 또는 MfaFailureHandler를 통해 이루어짐.

        throw new InvalidTransitionException(currentState, event);
    }
}
