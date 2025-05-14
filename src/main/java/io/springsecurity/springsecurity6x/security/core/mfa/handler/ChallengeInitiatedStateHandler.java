package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ChallengeInitiatedStateHandler implements MfaStateHandler {

    @Override
    public boolean supports(MfaState state) {
        // 특정 Factor에 대한 챌린지가 시작된 상태를 지원
        return state == MfaState.FACTOR_CHALLENGE_INITIATED;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        log.debug("[MFA Handler] ChallengeInitiatedStateHandler: Current state: {}, Event: {}, Factor: {}, Session ID: {}",
                ctx.getCurrentState(), event, ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());

        if (event == MfaEvent.SUBMIT_CREDENTIAL) {
            AuthType currentFactor = ctx.getCurrentProcessingFactor();
            if (currentFactor == null) {
                log.error("[MFA Handler] SUBMIT_CREDENTIAL event received, but no currentProcessingFactor in FactorContext. State: {}. Session ID: {}", ctx.getCurrentState(), ctx.getMfaSessionId());
                throw new IllegalStateException("Cannot process SUBMIT_CREDENTIAL without a currentProcessingFactor.");
            }
            // 각 Factor 타입에 따라 다음 "검증 대기" 상태로 전이
            // 이 부분은 MfaState enum 설계에 따라 더 세분화될 수 있음
            // (예: FORM_VERIFICATION_PENDING, OTT_VERIFICATION_PENDING 등)
            // 또는 하나의 FACTOR_VERIFICATION_PENDING 상태를 공유하고,
            // 실제 검증 로직은 Factor 타입에 따라 분기될 수 있음.
            // 여기서는 일반적인 검증 대기 상태로 전이한다고 가정.
            log.info("[MFA Handler] Credential submitted for factor: {}. Proceeding to verification. Session ID: {}", currentFactor, ctx.getMfaSessionId());
            return MfaState.FACTOR_VERIFICATION_PENDING;
        }
        log.warn("[MFA Handler] ChallengeInitiatedStateHandler: Unsupported event {} in state {} for factor {}. Session ID: {}",
                event, ctx.getCurrentState(), ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());
        throw new InvalidTransitionException(ctx.getCurrentState(), event);
    }
}
