package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler;
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
public class MfaAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler implements MfaFailureHandler {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final String initialDefaultFailureUrl;

    public MfaAuthenticationFailureHandler(String defaultFailureUrl,
                                           ContextPersistence contextPersistence,
                                           MfaPolicyProvider mfaPolicyProvider) {
        super(defaultFailureUrl);
        Assert.notNull(contextPersistence, "ContextPersistence cannot be null");
        Assert.notNull(mfaPolicyProvider, "MfaPolicyProvider cannot be null");
        this.contextPersistence = contextPersistence;
        this.mfaPolicyProvider = mfaPolicyProvider;
        this.initialDefaultFailureUrl = defaultFailureUrl;
    }

    /**
     * Spring Security의 AuthenticationFailureHandler 인터페이스 메서드.
     * MFA 실패 시 이 메서드가 호출되며, 내부적으로 onFactorFailure 또는 onGlobalMfaFailure로 분기합니다.
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        FactorContext factorContext = contextPersistence.contextLoad(request);
        AuthType currentProcessingFactor = null;

        if (factorContext != null) {
            currentProcessingFactor = factorContext.getCurrentProcessingFactor();
        }

        if (factorContext != null && currentProcessingFactor != null) {
            // 특정 Factor 처리 중 발생한 실패
            onFactorFailure(request, response, exception, currentProcessingFactor, factorContext);
        } else {
            // FactorContext가 없거나, 어떤 Factor 처리 중인지 알 수 없는 경우 (전역적 실패)
            onGlobalMfaFailure(request, response, exception, factorContext);
        }
    }

    /**
     * MfaFailureHandler 인터페이스 구현: 특정 MFA Factor 인증 시도 실패 시 호출.
     */
    @Override
    public void onFactorFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception,
                                AuthType failedFactorType, FactorContext factorContext) throws IOException, ServletException {

        Assert.notNull(factorContext, "FactorContext cannot be null for onFactorFailure");
        Assert.notNull(failedFactorType, "FailedFactorType cannot be null for onFactorFailure");

        log.warn("MFA Factor Failure: Factor '{}' for user '{}' (session ID: '{}') failed. Reason: {}",
                failedFactorType, factorContext.getUsername(), factorContext.getMfaSessionId(), exception.getMessage());

        factorContext.recordAttempt(failedFactorType, false, "Verification failed: " + exception.getMessage());
        int attempts = factorContext.getAttemptCount(failedFactorType);

        RetryPolicy retryPolicy = mfaPolicyProvider.getRetryPolicyForFactor(failedFactorType, factorContext);
        // RetryPolicy가 null일 경우를 대비하여 기본값 사용
        int maxAttempts = (retryPolicy != null) ? retryPolicy.getMaxAttempts() : 3;

        String finalRedirectUrl;
        if (attempts >= maxAttempts) {
            log.warn("MFA max attempts ({}) reached for factor {}. User: {}, Session: {}. Redirecting to terminal failure page.",
                    maxAttempts, failedFactorType, factorContext.getUsername(), factorContext.getMfaSessionId());
            factorContext.changeState(MfaState.MFA_FAILURE_TERMINAL);
            finalRedirectUrl = buildFailureUrl(this.initialDefaultFailureUrl, "max_attempts_exceeded", failedFactorType, 0);
            contextPersistence.deleteContext(request); // 실패 컨텍스트 삭제
        } else {
            log.info("MFA factor {} failed (attempt {}/{}). User: {}, Session: {}. Redirecting to factor selection.",
                    failedFactorType, attempts, maxAttempts, factorContext.getUsername(), factorContext.getMfaSessionId());
            factorContext.changeState(MfaState.AWAITING_MFA_FACTOR_SELECTION); // 재시도 가능 시, Factor 선택 화면으로 유도
            finalRedirectUrl = buildFailureUrl("/mfa/select-factor", "factor_auth_failed", failedFactorType, maxAttempts - attempts);
            contextPersistence.saveContext(factorContext, request); // 변경된 컨텍스트 저장
        }
        setDefaultFailureUrl(finalRedirectUrl); // 리다이렉션할 URL 설정
        super.onAuthenticationFailure(request, response, exception); // 부모 클래스의 실패 처리(리다이렉션) 호출
    }

    /**
     * MfaFailureHandler 인터페이스 구현: 전반적인 MFA 흐름 실패 또는 Factor를 특정할 수 없는 실패 시 호출.
     */
    @Override
    public void onGlobalMfaFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception,
                                   @Nullable FactorContext factorContext) throws IOException, ServletException {

        String username = (factorContext != null && factorContext.getUsername() != null) ? factorContext.getUsername() : "UnknownUser";
        String sessionId = (factorContext != null) ? factorContext.getMfaSessionId() : "NoMfaSession";

        log.warn("Global MFA Failure for user '{}' (MFA Session ID: '{}'). Reason: {}",
                username, sessionId, exception.getMessage());

        if (factorContext != null) {
            factorContext.changeState(MfaState.MFA_FAILURE_TERMINAL);
            contextPersistence.deleteContext(request); // 컨텍스트 삭제
        }

        String finalRedirectUrl = buildFailureUrl(this.initialDefaultFailureUrl, "mfa_global_failure", null, 0);
        setDefaultFailureUrl(finalRedirectUrl);
        super.onAuthenticationFailure(request, response, exception);
    }

    private String buildFailureUrl(String baseUrl, String errorKey, @Nullable AuthType factor, int attemptsLeft) {
        StringBuilder urlBuilder = new StringBuilder(baseUrl);
        urlBuilder.append(baseUrl.contains("?") ? "&" : "?").append("error=").append(errorKey);
        if (factor != null) {
            urlBuilder.append("&factor=").append(factor.name().toLowerCase());
        }
        if (attemptsLeft > 0) {
            urlBuilder.append("&attemptsLeft=").append(attemptsLeft);
        }
        log.debug("Constructed failure URL for MFA: {}", urlBuilder.toString());
        return urlBuilder.toString();
    }
}
