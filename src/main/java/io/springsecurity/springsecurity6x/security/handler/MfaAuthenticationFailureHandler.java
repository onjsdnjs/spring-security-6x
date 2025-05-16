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
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.util.Assert;

import java.io.IOException;

@Slf4j
public class MfaAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final String initialDefaultFailureUrl; // 생성자에서 설정된 기본 실패 URL을 저장

    public MfaAuthenticationFailureHandler(String defaultFailureUrl,
                                           ContextPersistence contextPersistence,
                                           MfaPolicyProvider mfaPolicyProvider) {
        super(defaultFailureUrl); // 부모 클래스에 초기 기본 실패 URL 설정
        Assert.notNull(contextPersistence, "ContextPersistence cannot be null");
        Assert.notNull(mfaPolicyProvider, "MfaPolicyProvider cannot be null");
        this.contextPersistence = contextPersistence;
        this.mfaPolicyProvider = mfaPolicyProvider;
        this.initialDefaultFailureUrl = defaultFailureUrl; // 동적 URL 구성의 기반으로 사용하기 위해 저장
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        FactorContext factorContext = contextPersistence.contextLoad(request);
        String finalRedirectUrl; // 최종적으로 리다이렉션될 URL

        if (factorContext != null) {
            AuthType currentFactor = factorContext.getCurrentProcessingFactor();
            log.warn("MFA Step Failure: Factor {} for user {} (session {}) failed. Reason: {}",
                    currentFactor != null ? currentFactor : "N/A",
                    factorContext.getUsername(),
                    factorContext.getMfaSessionId(),
                    exception.getMessage());

            if (currentFactor != null) {
                factorContext.recordAttempt(currentFactor, false, "Verification failed: " + exception.getMessage());
                int attempts = factorContext.getAttemptCount(currentFactor);

                RetryPolicy retryPolicy = (this.mfaPolicyProvider != null) ?
                        this.mfaPolicyProvider.getRetryPolicyForFactor(currentFactor, factorContext) : RetryPolicy.defaultPolicy();
                int maxAttempts = (retryPolicy != null) ? retryPolicy.getMaxAttempts() : 3; // 기본값

                if (attempts >= maxAttempts) {
                    log.warn("MFA max attempts reached for factor {}. User: {}, Session: {}. Redirecting to terminal failure.",
                            currentFactor, factorContext.getUsername(), factorContext.getMfaSessionId());
                    factorContext.changeState(MfaState.MFA_FAILURE_TERMINAL);
                    // 최종 실패 시에는 생성자에서 설정된 기본 실패 URL(initialDefaultFailureUrl)에 파라미터 추가
                    finalRedirectUrl = buildFailureUrl(this.initialDefaultFailureUrl, "max_attempts_exceeded", currentFactor, 0);
                    contextPersistence.deleteContext(request);
                } else {
                    // 재시도 가능: 다음 Factor 선택 페이지로 안내하고, 실패 정보와 남은 시도 횟수 전달
                    factorContext.changeState(MfaState.AWAITING_MFA_FACTOR_SELECTION);
                    finalRedirectUrl = buildFailureUrl("/mfa/select-factor", "factor_auth_failed", currentFactor, maxAttempts - attempts);
                }
                contextPersistence.saveContext(factorContext, request);
            } else {
                // currentFactor가 null인 경우 (예: FactorContext는 있지만 어떤 Factor 처리 중인지 모를 때)
                log.warn("MFA Failure Handler: currentProcessingFactor is null in FactorContext. Session: {}. Using configured default failure URL.", factorContext.getMfaSessionId());
                finalRedirectUrl = buildFailureUrl(this.initialDefaultFailureUrl, "mfa_context_error", null, 0);
                contextPersistence.deleteContext(request); // 불완전한 컨텍스트는 삭제
            }
        } else {
            // FactorContext 자체가 없는 경우 (MFA 흐름 시작 전 또는 세션 만료 등)
            log.warn("MFA Failure Handler: FactorContext is null. Using configured default failure URL. Exception: {}", exception.getMessage());
            finalRedirectUrl = buildFailureUrl(this.initialDefaultFailureUrl, "mfa_session_not_found", null, 0);
        }

        // SimpleUrlAuthenticationFailureHandler가 사용할 최종 실패 URL 설정
        setDefaultFailureUrl(finalRedirectUrl);
        // 부모 클래스의 실패 처리 로직(리다이렉션 등) 실행
        super.onAuthenticationFailure(request, response, exception);
    }

    private String buildFailureUrl(String baseUrl, String errorKey, @Nullable AuthType factor, int attemptsLeft) {
        StringBuilder urlBuilder = new StringBuilder(baseUrl);
        // URL에 이미 파라미터가 있는지 확인하여 '?' 또는 '&'를 적절히 사용
        urlBuilder.append(baseUrl.contains("?") ? "&" : "?").append("error=").append(errorKey);
        if (factor != null) {
            urlBuilder.append("&factor=").append(factor.name().toLowerCase());
        }
        if (attemptsLeft > 0) {
            urlBuilder.append("&attemptsLeft=").append(attemptsLeft);
        }
        log.debug("Constructed failure URL: {}", urlBuilder.toString());
        return urlBuilder.toString();
    }
}
