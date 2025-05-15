package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.io.IOException;

@Slf4j
public class MfaAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider; // 재시도 정책 등을 위해 주입 (선택적)

    public MfaAuthenticationFailureHandler(String defaultFailureUrl, ContextPersistence contextPersistence, MfaPolicyProvider mfaPolicyProvider) {
        super(defaultFailureUrl); // 예: "/mfa/failure"
        this.contextPersistence = contextPersistence;
        this.mfaPolicyProvider = mfaPolicyProvider;
        // setUseForward(true); // 필요에 따라 Forward 방식 사용
    }
    // 간소화된 생성자 (기본 실패 URL만)
    public MfaAuthenticationFailureHandler(String defaultFailureUrl, ContextPersistence contextPersistence) {
        super(defaultFailureUrl);
        this.contextPersistence = contextPersistence;
        this.mfaPolicyProvider = null; // 기본 재시도 정책은 FactorContext에서 관리한다고 가정
    }


    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        FactorContext factorContext = contextPersistence.contextLoad(request);
        String failureRedirectUrl = getFailureUrl(request, exception); // 기본 실패 URL 또는 커스텀 URL

        if (factorContext != null) {
            AuthType currentFactor = factorContext.getCurrentProcessingFactor();
            log.warn("MFA Step Failure: Factor {} for user {} (session {}) failed. Reason: {}",
                    currentFactor, factorContext.getUsername(), factorContext.getMfaSessionId(), exception.getMessage());

            factorContext.recordAttempt(currentFactor, false, "Verification failed: " + exception.getMessage());
            int attempts = factorContext.getAttemptCount(currentFactor);

            RetryPolicy retryPolicy = mfaPolicyProvider != null ? mfaPolicyProvider.getRetryPolicyForFactor(currentFactor, factorContext) : RetryPolicy.defaultPolicy();
            int maxAttempts = retryPolicy.getMaxAttempts();

            if (attempts >= maxAttempts) {
                log.warn("MFA max attempts reached for factor {}. User: {}, Session: {}. Redirecting to terminal failure.",
                        currentFactor, factorContext.getUsername(), factorContext.getMfaSessionId());
                factorContext.changeState(MfaState.MFA_FAILURE_TERMINAL);
                failureRedirectUrl = getFailureUrl(request, exception) + "?error=max_attempts_exceeded&factor=" + currentFactor.name().toLowerCase();
                contextPersistence.deleteContext(request); // 최종 실패 시 컨텍스트 삭제
            } else {
                factorContext.changeState(MfaState.AWAITING_MFA_FACTOR_SELECTION); // 다시 Factor 선택으로 유도
                failureRedirectUrl = "/mfa/select-factor?error=factor_auth_failed&factor=" + currentFactor.name().toLowerCase() + "&attemptsLeft=" + (maxAttempts - attempts);
            }
            contextPersistence.saveContext(factorContext, request);
            setDefaultFailureUrl(failureRedirectUrl); // 리다이렉션 URL 동적 변경
        } else {
            log.warn("MFA Failure Handler: FactorContext is null. Standard redirection to {}.", failureRedirectUrl);
            setDefaultFailureUrl(failureRedirectUrl + "?error=mfa_session_not_found");
        }

        super.onAuthenticationFailure(request, response, exception);
    }

    private String getFailureUrl(HttpServletRequest request, AuthenticationException exception) {
        // 요청 파라미터나 세션, 예외 타입에 따라 다른 실패 URL을 반환할 수 있음
        // 여기서는 생성자에서 받은 기본 URL을 사용
//        return super.getDefaultFailureUrl();
        return "/failure";
    }
}
