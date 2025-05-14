package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.Assert;

@Slf4j
public class VerificationPendingStateHandler implements MfaStateHandler {

    private final MfaPolicyProvider policyProvider;

    public VerificationPendingStateHandler(MfaPolicyProvider policyProvider) {
        Assert.notNull(policyProvider, "MfaPolicyProvider cannot be null");
        this.policyProvider = policyProvider;
    }

    @Override
    public boolean supports(MfaState state) {
        return state == MfaState.FACTOR_VERIFICATION_PENDING ||
                state == MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING; // 자동 시도 검증 상태도 여기서 처리
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        AuthType currentFactor = ctx.getCurrentProcessingFactor();
        MfaState currentState = ctx.getCurrentState(); // 현재 상태 기록

        log.debug("[MFA Handler] VerificationPendingState: Current state: {}, Event: {}, Factor: {}, Session ID: {}",
                currentState, event, currentFactor, ctx.getMfaSessionId());

        if (currentFactor == null) {
            log.error("[MFA Handler] Event {} received in state {}, but no currentProcessingFactor in FactorContext. Session ID: {}", event, currentState, ctx.getMfaSessionId());
            // currentFactor가 null 이면 어떤 Factor에 대한 검증인지 알 수 없으므로 오류 처리
            return MfaState.MFA_SYSTEM_ERROR; // 또는 MFA_FAILURE_TERMINAL
        }

        // MfaEvent enum에 VERIFICATION_SUCCESS와 VERIFICATION_FAILURE가 정의되어 있어야 합니다.
        if (event == MfaEvent.VERIFICATION_SUCCESS) {
            ctx.recordAttempt(currentFactor, true, "Verification successful for " + currentFactor);
            if (currentState == MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING) {
                ctx.setAutoAttemptFactorSucceeded(true); // FactorContext에 setAutoAttemptFactorSucceeded(boolean) 메소드 필요
            }

            // MfaPolicyProvider를 사용하여 다음 단계를 결정
            AuthType nextFactor = policyProvider.determineNextFactor(ctx); // MfaPolicyProvider에 determineNextFactor(FactorContext) 메소드 필요

            if (nextFactor != null) {
                log.info("[MFA Handler] Factor {} verified. Next factor to process: {}. Session ID: {}", currentFactor, nextFactor, ctx.getMfaSessionId());
                ctx.setCurrentProcessingFactor(nextFactor);
                return MfaState.FACTOR_CHALLENGE_INITIATED; // 다음 Factor 챌린지 시작
            } else {
                // 모든 필수 Factor가 완료된 경우
                log.info("[MFA Handler] All required MFA factors verified for user: {}. Proceeding to token issuance. Session ID: {}", ctx.getUsername(), ctx.getMfaSessionId());
                return MfaState.MFA_VERIFICATION_COMPLETED; // 또는 TOKEN_ISSUANCE_REQUIRED (새로운 enum 값에 따름)
            }
        } else if (event == MfaEvent.VERIFICATION_FAILURE) {
            ctx.recordAttempt(currentFactor, false, "Verification failed for " + currentFactor);
            if (currentState == MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING) {
                ctx.setAutoAttemptFactorSkippedOrFailed(true); // FactorContext에 setAutoAttemptFactorSkippedOrFailed(boolean) 메소드 필요
                log.warn("[MFA Handler] Auto-attempt factor ({}) verification failed. Proceeding to factor selection. Session ID: {}", currentFactor, ctx.getMfaSessionId());
                return MfaState.AWAITING_MFA_FACTOR_SELECTION;
            }

            int attempts = ctx.incrementAttemptCountForCurrentFactor();
            RetryPolicy retryPolicy = policyProvider.getRetryPolicyForFactor(currentFactor, ctx); // MfaPolicyProvider에 getRetryPolicyForFactor(...) 메소드 필요

            if (retryPolicy == null) {
                log.error("[MFA Handler] RetryPolicy not found for factor {}. Treating as max attempts reached. Session ID: {}", currentFactor, ctx.getMfaSessionId());
                return MfaState.MFA_FAILURE_TERMINAL;
            }

            int maxAttempts = retryPolicy.getMaxAttempts(); // RetryPolicy에 getMaxAttempts() 메소드 필요

            if (attempts >= maxAttempts) {
                log.warn("[MFA Handler] Max verification attempts ({}) reached for factor {} for user: {}. Session ID: {}",
                        maxAttempts, currentFactor, ctx.getUsername(), ctx.getMfaSessionId());
                return MfaState.MFA_FAILURE_TERMINAL;
            } else {
                log.warn("[MFA Handler] Verification failed for factor {} (attempt {}/{}). Retrying challenge. Session ID: {}",
                        currentFactor, attempts, maxAttempts, ctx.getMfaSessionId());
                return MfaState.FACTOR_CHALLENGE_INITIATED; // 동일 Factor 챌린지 재시도
            }
        }
        log.warn("[MFA Handler] VerificationPendingStateHandler: Unsupported event {} in state {} for factor {}. Session ID: {}",
                event, currentState, currentFactor, ctx.getMfaSessionId());
        throw new InvalidTransitionException(currentState, event);
    }
}

