package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import lombok.RequiredArgsConstructor; // 추가
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.Assert;

@Slf4j
@RequiredArgsConstructor // MfaPolicyProvider 주입
public class VerificationPendingStateHandler implements MfaStateHandler {

    private final MfaPolicyProvider mfaPolicyProvider;

    @Override
    public boolean supports(MfaState state) {
        // 이 핸들러는 스프링 시큐리티 필터가 Factor 검증을 시도하는 동안의 상태,
        // 또는 검증 직후 결과를 처리하기 위한 상태를 지원.
        // 사용자가 제공한 MfaState.java 에는 FACTOR_VERIFICATION_PENDING 상태가 없음.
        // FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION 상태에서 검증이 이루어지고,
        // 그 결과(VERIFICATION_SUCCESS/FAILURE)에 따라 이 핸들러가 호출된다고 가정.
        // 또는, MfaStepBasedSuccessHandler/MfaAuthenticationFailureHandler가 직접 다음 상태를 결정.
        // 여기서는 MfaStepBasedSuccess/FailureHandler가 이 핸들러를 호출한다고 가정하고,
        // supports는 FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION을 지원하도록 수정.
        // 또는, 스프링 필터 처리 후 호출되는 Success/Failure Handler가 직접 다음 상태를 결정하는 것이 더 자연스러움.

        // **수정된 접근**: 이 핸들러는 MfaStepBasedSuccessHandler와 MfaAuthenticationFailureHandler에 의해
        // VERIFICATION_SUCCESS 또는 VERIFICATION_FAILURE 이벤트와 함께 호출된다고 가정.
        // 호출 시점의 상태는 FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION 일 것임.
        return state == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        AuthType currentFactor = ctx.getCurrentProcessingFactor();
        MfaState currentState = ctx.getCurrentState(); // 현재 상태 (FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)

        log.debug("[MFA StateHandler] VerificationOutcomeProcessing: Current state: {}, Event: {}, Factor: {}, User: {}, Session ID: {}",
                currentState, event, currentFactor, ctx.getUsername(), ctx.getMfaSessionId());

        if (currentFactor == null) {
            log.error("Event {} received but no currentProcessingFactor in FactorContext. State: {}, User: {}, Session ID: {}",
                    event, currentState, ctx.getUsername(), ctx.getMfaSessionId());
            return MfaState.MFA_SYSTEM_ERROR;
        }

        if (event == MfaEvent.VERIFICATION_SUCCESS) {
            ctx.addCompletedFactor(currentFactor); // 성공한 Factor 기록
            ctx.recordAttempt(currentFactor, true, "Verification successful for " + currentFactor);

            // 자동 시도였는지 여부 확인 및 처리 (FactorContext에 autoAttemptFactorSucceeded 필드 필요)
            // if (currentState == MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING) { // 이 상태가 MfaState.java에 없다면 조건 제거
            //     ctx.setAutoAttemptFactorSucceeded(true);
            // }

            AuthType nextFactor = mfaPolicyProvider.determineNextFactorToProcess(ctx);
            if (nextFactor != null) {
                log.info("Factor {} verified for user '{}'. Next factor to process: {}. Session ID: {}",
                        currentFactor, ctx.getUsername(), nextFactor, ctx.getMfaSessionId());
                ctx.setCurrentProcessingFactor(nextFactor);
                return MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION; // 다음 Factor 챌린지 시작
            } else {
                // 모든 필수 Factor 완료
                log.info("All required MFA factors verified for user '{}'. Proceeding to ALL_FACTORS_COMPLETED. Session ID: {}",
                        ctx.getUsername(), ctx.getMfaSessionId());
                return MfaState.ALL_FACTORS_COMPLETED; // 모든 Factor 완료 상태로
            }
        } else if (event == MfaEvent.VERIFICATION_FAILURE) {
            ctx.recordAttempt(currentFactor, false, "Verification failed for " + currentFactor);

            // 자동 시도 실패 처리 (FactorContext에 autoAttemptFactorSkippedOrFailed 필드 필요)
            // if (currentState == MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING) { // 이 상태가 MfaState.java에 없다면 조건 제거
            //     ctx.setAutoAttemptFactorSkippedOrFailed(true);
            //     log.warn("Auto-attempt factor ({}) verification failed for user '{}'. Proceeding to factor selection. Session ID: {}",
            // currentFactor, ctx.getUsername(), ctx.getMfaSessionId());
            //     ctx.setCurrentProcessingFactor(null); // 현재 처리 Factor 초기화
            //     return MfaState.AWAITING_FACTOR_SELECTION;
            // }

            // 수동 Factor 검증 실패
            int attempts = ctx.getAttemptCount(currentFactor); // 이미 incrementAttemptCount는 recordAttempt 내부 또는 호출부에서 수행 가정
            RetryPolicy retryPolicy = mfaPolicyProvider.getRetryPolicyForFactor(currentFactor, ctx);
            int maxAttempts = (retryPolicy != null) ? retryPolicy.getMaxAttempts() : 3; // 기본값

            if (attempts >= maxAttempts) {
                log.warn("Max verification attempts ({}) reached for factor {} for user '{}'. MFA flow terminated. Session ID: {}",
                        maxAttempts, currentFactor, ctx.getUsername(), ctx.getMfaSessionId());
                return MfaState.MFA_FAILED_TERMINAL; // 최대 시도 초과 시 최종 실패
            } else {
                log.warn("Verification failed for factor {} for user '{}' (attempt {}/{}). Returning to factor selection. Session ID: {}",
                        currentFactor, ctx.getUsername(), attempts, maxAttempts, ctx.getMfaSessionId());
                ctx.setCurrentProcessingFactor(null); // 현재 처리 Factor 초기화
                return MfaState.AWAITING_FACTOR_SELECTION; // 재시도 가능 시 Factor 선택 화면으로
            }
        } else if (event == MfaEvent.TIMEOUT) { // 타임아웃 이벤트 처리
            log.warn("MFA session timeout occurred during verification for factor {} for user '{}'. Session ID: {}",
                    currentFactor, ctx.getUsername(), ctx.getMfaSessionId());
            return MfaState.MFA_SESSION_EXPIRED;
        }

        log.warn("VerificationPendingStateHandler: Unsupported event {} received in state {} for factor {}. User: {}, Session ID: {}",
                event, currentState, currentFactor, ctx.getUsername(), ctx.getMfaSessionId());
        throw new InvalidTransitionException(currentState, event);
    }
}