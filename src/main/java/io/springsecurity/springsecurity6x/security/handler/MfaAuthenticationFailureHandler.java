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
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.io.IOException;

@Slf4j
@Component
public class MfaAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider; // 이제 final로 유지 가능

    public MfaAuthenticationFailureHandler(String defaultFailureUrl,
                                           ContextPersistence contextPersistence,
                                           @Nullable MfaPolicyProvider mfaPolicyProvider) {
        super(defaultFailureUrl); // 부모 생성자 호출
        Assert.notNull(contextPersistence, "ContextPersistence cannot be null");
        this.contextPersistence = contextPersistence;
        this.mfaPolicyProvider = mfaPolicyProvider; // null일 수 있음 (호출하는 쪽에서 new RetryPolicy(3) 등으로 기본값 제공 가능)
    }

    public MfaAuthenticationFailureHandler(ContextPersistence contextPersistence,
                                           MfaPolicyProvider mfaPolicyProvider) {
        super(); // 또는 super("/default/failure/path");
        Assert.notNull(contextPersistence, "ContextPersistence cannot be null");
        Assert.notNull(mfaPolicyProvider, "MfaPolicyProvider cannot be null");
        this.contextPersistence = contextPersistence;
        this.mfaPolicyProvider = mfaPolicyProvider;
    }


    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        FactorContext factorContext = contextPersistence.contextLoad(request);
        String originalFailureUrl = this.getFailureUrlFromRequestOrSession(request, exception);

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

                RetryPolicy retryPolicy = (mfaPolicyProvider != null) ?
                        mfaPolicyProvider.getRetryPolicyForFactor(currentFactor, factorContext) : RetryPolicy.defaultPolicy();
                int maxAttempts = (retryPolicy != null) ? retryPolicy.getMaxAttempts() : 3; // 기본값 설정

                if (attempts >= maxAttempts) {
                    log.warn("MFA max attempts reached for factor {}. User: {}, Session: {}. Redirecting to terminal failure.",
                            currentFactor, factorContext.getUsername(), factorContext.getMfaSessionId());
                    factorContext.changeState(MfaState.MFA_FAILURE_TERMINAL);
                    setDefaultFailureUrl(buildFailureUrl(originalFailureUrl, "max_attempts_exceeded", currentFactor, 0));
                    contextPersistence.deleteContext(request); // 최종 실패 시 컨텍스트 삭제
                } else {
                    factorContext.changeState(MfaState.AWAITING_MFA_FACTOR_SELECTION); // 다시 Factor 선택으로 유도
                    setDefaultFailureUrl(buildFailureUrl("/mfa/select-factor", "factor_auth_failed", currentFactor, maxAttempts - attempts));
                }
                contextPersistence.saveContext(factorContext, request);
            } else {
                // currentFactor가 null 이면, 1차 인증 실패 후 MFA 컨텍스트가 생성되지 않았거나,
                // 다른 경로의 실패일 수 있음. 일반 실패 URL로 리다이렉트.
                log.warn("MFA Failure Handler: currentProcessingFactor is null in FactorContext. Session: {}. Standard redirection.", factorContext.getMfaSessionId());
                setDefaultFailureUrl(buildFailureUrl(originalFailureUrl, "mfa_context_error", null, 0));
                contextPersistence.deleteContext(request); // 불완전한 컨텍스트는 삭제
            }
        } else {
            log.warn("MFA Failure Handler: FactorContext is null. Standard redirection. Exception: {}", exception.getMessage());
            // MFA 컨텍스트가 아예 없는 경우 (예: 1차 인증 실패)
            setDefaultFailureUrl(buildFailureUrl(originalFailureUrl, "mfa_session_not_found", null, 0));
        }

        super.onAuthenticationFailure(request, response, exception);
    }

    private String getFailureUrlFromRequestOrSession(HttpServletRequest request, AuthenticationException exception) {
        // SimpleUrlAuthenticationFailureHandler의 기본 로직을 활용하거나 커스텀 로직 구현
        // 여기서는 생성자에서 설정된 defaultFailureUrl을 사용하도록 유도
        // (또는 부모의 determineFailureUrl을 호출할 수도 있으나, protected임)
        // return super.determineFailureUrl(request, exception); // 접근 불가
        // 가장 간단하게는 현재 설정된 기본 실패 URL을 가져오는 방법이 없음.
        // 따라서, 생성자에서 받은 URL을 기반으로 하거나,
        // MfaInfrastructureAutoConfiguration에서 주입받은 AuthContextProperties를 여기서도 사용
        return "/mfa/failure"; // 임시 기본값
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
        return urlBuilder.toString();
    }
}
