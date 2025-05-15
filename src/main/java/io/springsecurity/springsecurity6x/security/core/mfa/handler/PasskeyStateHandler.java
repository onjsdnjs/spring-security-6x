package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;     // 새로운 MfaState 사용
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException; // 가정된 경로

public class PasskeyStateHandler implements MfaStateHandler {

    @Override
    public boolean supports(MfaState state) {
        // Passkey 자동 시도 관련 상태 및 수동 Passkey 처리 상태를 지원
        return state == MfaState.AUTO_ATTEMPT_FACTOR_PENDING ||
                state == MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING ||
                state == MfaState.FACTOR_CHALLENGE_INITIATED ||
                state == MfaState.FACTOR_VERIFICATION_PENDING;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {

        MfaState currentState = ctx.getCurrentState();
        AuthType preferredAutoFactor = ctx.getPreferredAutoAttemptFactor();
        AuthType currentProcessingFactor = getAuthType(ctx, currentState, preferredAutoFactor);

        // Passkey 자동 시도 단계
        if (currentState == MfaState.AUTO_ATTEMPT_FACTOR_PENDING && preferredAutoFactor == AuthType.PASSKEY) {
            if (event == MfaEvent.CHALLENGE_INITIATED) { // Conditional UI 챌린지 생성/요청 성공
                ctx.getLastActivityTimestamp();
                return MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING;

            } else if (event == MfaEvent.SUBMIT_CREDENTIAL) { // 사용자가 Conditional UI에서 Passkey 선택 및 응답 제출
                ctx.getLastActivityTimestamp();
                return MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING; // 검증 대기

            } else if (event == MfaEvent.SKIP_AUTO_ATTEMPT || event == MfaEvent.ERROR) { // 자동 시도 건너뛰기 또는 챌린지 생성 실패
                ctx.setAutoAttemptFactorSkippedOrFailed(true);
                return MfaState.AWAITING_MFA_FACTOR_SELECTION;
            }
        }
        // 사용자가 명시적으로 Passkey를 선택한 후의 단계
        else if (currentState == MfaState.FACTOR_CHALLENGE_INITIATED && currentProcessingFactor == AuthType.PASSKEY) {
            if (event == MfaEvent.SUBMIT_CREDENTIAL) { // Passkey Assertion 제출
                ctx.getLastActivityTimestamp();
                return MfaState.FACTOR_VERIFICATION_PENDING;
            } else if (event == MfaEvent.ERROR) { // 챌린지 생성/요청 중 오류
                return MfaState.AWAITING_MFA_FACTOR_SELECTION;
            }
        }
        // AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING 또는 FACTOR_VERIFICATION_PENDING 상태에서의
        // VERIFICATION_SUCCESS, VERIFICATION_FAILURE 이벤트는 MfaContinuationHandler/MfaFailureHandler에서 처리 후 상태 변경.
        // 이 핸들러가 직접 최종 상태로 전이시키지 않음.
        else if (currentState == MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING || currentState == MfaState.FACTOR_VERIFICATION_PENDING) {
            if (event == MfaEvent.TIMEOUT) {
                return MfaState.MFA_SESSION_INVALIDATED;
            }
        }
        throw new InvalidTransitionException(currentState, event);
    }

    private static AuthType getAuthType(FactorContext ctx, MfaState currentState, AuthType preferredAutoFactor) {
        AuthType currentProcessingFactor = ctx.getCurrentProcessingFactor();

        boolean isAutoAttemptPasskey = (currentState == MfaState.AUTO_ATTEMPT_FACTOR_PENDING || currentState == MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING) && preferredAutoFactor == AuthType.PASSKEY;
        boolean isManualPasskey = (currentState == MfaState.FACTOR_CHALLENGE_INITIATED || currentState == MfaState.FACTOR_VERIFICATION_PENDING) && currentProcessingFactor == AuthType.PASSKEY;

        if (!isAutoAttemptPasskey && !isManualPasskey) {
            throw new IllegalStateException("PasskeyStateHandler called for a non-Passkey operation or incorrect state. Current Factor: " + currentProcessingFactor + ", Preferred Auto: " + preferredAutoFactor + ", State: " + currentState);
        }
        return currentProcessingFactor;
    }
}
