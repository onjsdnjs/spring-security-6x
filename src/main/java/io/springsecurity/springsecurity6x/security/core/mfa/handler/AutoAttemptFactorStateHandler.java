package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AutoAttemptFactorStateHandler implements MfaStateHandler {

    @Override
    public boolean supports(MfaState state) {
        return state == MfaState.AUTO_ATTEMPT_FACTOR_PENDING ||
                state == MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        MfaState currentState = ctx.getCurrentState();
        log.debug("[MFA Handler] AutoAttemptFactorState: Current state: {}, Event: {}, Factor: {}, Session ID: {}",
                currentState, event, ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());

        if (currentState == MfaState.AUTO_ATTEMPT_FACTOR_PENDING) {
            if (event == MfaEvent.REQUEST_CHALLENGE) {
                // 자동 시도 Factor에 대한 챌린지 요청 (예: Passkey Conditional UI의 get() 호출)
                log.info("[MFA Handler] Auto-attempt factor ({}) challenge requested. Session ID: {}", ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());
                return MfaState.FACTOR_CHALLENGE_INITIATED; // 일반적인 Factor 챌린지 시작 상태로 통합
            } else if (event == MfaEvent.SUBMIT_CREDENTIAL) {
                // 사용자가 자동 시도 Factor에 응답한 경우 (예: Passkey Conditional UI에서 바로 자격증명 선택)
                log.info("[MFA Handler] Auto-attempt factor ({}) credential submitted directly. Proceeding to verification. Session ID: {}", ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());
                return MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING; // 자동 시도 Factor 검증 상태로
            } else if (event == MfaEvent.RECOVER) { // 사용자가 자동 시도를 건너뛰고 다른 Factor 선택을 원할 경우
                log.info("[MFA Handler] User chose to skip auto-attempt factor. Proceeding to factor selection. Session ID: {}", ctx.getMfaSessionId());
                ctx.setAutoAttemptFactorSkippedOrFailed(true);
                return MfaState.AWAITING_MFA_FACTOR_SELECTION;
            }
        } else if (currentState == MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING) {
            // 이 상태는 VerificationPendingStateHandler에서 처리하거나,
            // 여기서 VERIFICATION_SUCCESS/FAILURE 이벤트를 받아 처리할 수 있음.
            // 여기서는 VerificationPendingStateHandler로 책임을 넘긴다고 가정하고,
            // SUBMIT_CREDENTIAL 이벤트는 이미 위에서 처리했으므로, 여기서는 다른 이벤트만 고려.
            // 만약 이 핸들러에서 직접 성공/실패를 처리한다면 아래와 같이 구현.
            /*
            if (event == MfaEvent.VERIFICATION_SUCCESS) {
                log.info("[MFA Handler] Auto-attempt factor ({}) verification successful. Session ID: {}", ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());
                ctx.setAutoAttemptFactorSucceeded(true);
                // 모든 MFA가 완료되었는지 확인 후 다음 상태 결정 (MfaPolicyProvider 사용)
                // return MfaState.TOKEN_ISSUANCE_REQUIRED; 또는 MfaState.AWAITING_MFA_FACTOR_SELECTION;
            } else if (event == MfaEvent.VERIFICATION_FAILURE) {
                log.warn("[MFA Handler] Auto-attempt factor ({}) verification failed. Session ID: {}", ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());
                ctx.setAutoAttemptFactorSkippedOrFailed(true);
                return MfaState.AWAITING_MFA_FACTOR_SELECTION; // 다른 Factor 선택으로 유도
            }
            */
            // 여기서는 AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING 상태에서 다른 이벤트는 예외 처리
            log.warn("[MFA Handler] AutoAttemptFactorState: Unsupported event {} in state {}. Session ID: {}", event, currentState, ctx.getMfaSessionId());
            throw new InvalidTransitionException(currentState, event);
        }

        log.warn("[MFA Handler] AutoAttemptFactorState: Unsupported event {} in state {}. Session ID: {}", event, currentState, ctx.getMfaSessionId());
        throw new InvalidTransitionException(currentState, event);
    }
}

