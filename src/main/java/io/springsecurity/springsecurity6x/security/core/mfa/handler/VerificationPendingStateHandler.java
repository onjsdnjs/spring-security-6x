package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.Assert;

@Slf4j
public class VerificationPendingStateHandler implements MfaStateHandler {

    private final MfaPolicyProvider policyProvider; // 다음 Factor 결정 등에 사용

    public VerificationPendingStateHandler(MfaPolicyProvider policyProvider) {
        Assert.notNull(policyProvider, "MfaPolicyProvider cannot be null");
        this.policyProvider = policyProvider;
    }

    @Override
    public boolean supports(MfaState state) {
        // Factor의 인증 정보가 제출되어 검증 대기 중인 상태를 지원
        return state == MfaState.FACTOR_VERIFICATION_PENDING;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        AuthType currentFactor = ctx.getCurrentProcessingFactor();
        log.debug("[MFA Handler] VerificationPendingStateHandler: Current state: {}, Event: {}, Factor: {}, Session ID: {}",
                ctx.getCurrentState(), event, currentFactor, ctx.getMfaSessionId());

        if (event == MfaEvent.VERIFICATION_SUCCESS) {
            ctx.recordAttempt(currentFactor, true, "Verification successful for " + currentFactor);
            ctx.setAutoAttemptFactorSucceeded(ctx.getPreferredAutoAttemptFactor() == currentFactor); // 자동 시도 Factor 성공 여부 업데이트

            // MfaPolicyProvider를 사용하여 다음 단계를 결정
            AuthType nextFactor = policyProvider.determineNextFactor(ctx);

            if (nextFactor != null) {
                log.info("[MFA Handler] Factor {} verified. Next factor to process: {}. Session ID: {}", currentFactor, nextFactor, ctx.getMfaSessionId());
                ctx.setCurrentProcessingFactor(nextFactor);
                return MfaState.FACTOR_CHALLENGE_INITIATED; // 다음 Factor 챌린지 시작
            } else {
                // 모든 필수 Factor가 완료된 경우
                log.info("[MFA Handler] All required MFA factors verified for user: {}. Proceeding to token issuance. Session ID: {}", ctx.getUsername(), ctx.getMfaSessionId());
                return MfaState.TOKEN_ISSUANCE_REQUIRED; // 토큰 발급 단계로
            }
        } else if (event == MfaEvent.VERIFICATION_FAILURE) {
            ctx.recordAttempt(currentFactor, false, "Verification failed for " + currentFactor);
            int attempts = ctx.incrementAttemptCountForCurrentFactor();
            int maxAttempts = policyProvider.getRetryPolicyForFactor(currentFactor, ctx).getMaxAttempts(); // Factor별 재시도 정책

            if (attempts >= maxAttempts) {
                log.warn("[MFA Handler] Max verification attempts ({}) reached for factor {} for user: {}. Session ID: {}",
                        maxAttempts, currentFactor, ctx.getUsername(), ctx.getMfaSessionId());
                // 최대 시도 횟수 초과 시 MFA 실패 처리
                return MfaState.MFA_FAILURE_TERMINAL;
            } else {
                log.warn("[MFA Handler] Verification failed for factor {} (attempt {}/{}). Retrying challenge. Session ID: {}",
                        currentFactor, attempts, maxAttempts, ctx.getMfaSessionId());
                // 재시도: 동일 Factor 챌린지 다시 시작
                return MfaState.FACTOR_CHALLENGE_INITIATED;
            }
        }
        log.warn("[MFA Handler] VerificationPendingStateHandler: Unsupported event {} in state {} for factor {}. Session ID: {}",
                event, ctx.getCurrentState(), currentFactor, ctx.getMfaSessionId());
        throw new InvalidTransitionException(ctx.getCurrentState(), event);
    }
}
