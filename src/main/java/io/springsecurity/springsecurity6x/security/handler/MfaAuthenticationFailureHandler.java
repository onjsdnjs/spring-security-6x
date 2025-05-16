package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter; // 추가
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler; // Spring Security 인터페이스
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.io.IOException;
import java.util.HashMap; // 추가
import java.util.Map;    // 추가

@Slf4j
@Component
@RequiredArgsConstructor
public class MfaAuthenticationFailureHandler implements AuthenticationFailureHandler, io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthResponseWriter responseWriter;
    private final String defaultFailureRedirectUrl = "/loginForm?error"; // 일반적인 기본 실패 URL (클라이언트가 사용할 수도 있음)
    private final String mfaSelectFactorUrl = "/mfa/select-factor"; // MFA 재시도 시 안내 URL

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
            onFactorFailure(request, response, exception, currentProcessingFactor, factorContext);
        } else {
            onGlobalMfaFailure(request, response, exception, factorContext);
        }
    }

    @Override
    public void onFactorFailure(HttpServletRequest request,
                                HttpServletResponse response,
                                AuthenticationException exception,
                                AuthType failedFactorType,
                                FactorContext factorContext) throws IOException, ServletException {
        Assert.notNull(factorContext, "FactorContext cannot be null for onFactorFailure");
        Assert.notNull(failedFactorType, "FailedFactorType cannot be null for onFactorFailure");

        String usernameForLog = factorContext.getUsername() != null ? factorContext.getUsername() : "UnknownUser";
        log.warn("MFA Factor Failure: Factor '{}' for user '{}' (session ID: '{}') failed. Reason: {}",
                failedFactorType, usernameForLog, factorContext.getMfaSessionId(), exception.getMessage());

        factorContext.recordAttempt(failedFactorType, false, "Verification failed: " + exception.getMessage());
        int attempts = factorContext.getAttemptCount(failedFactorType);
        RetryPolicy retryPolicy = mfaPolicyProvider.getRetryPolicyForFactor(failedFactorType, factorContext);
        int maxAttempts = (retryPolicy != null) ? retryPolicy.getMaxAttempts() : 3;

        Map<String, Object> errorDetails = new HashMap<>();
        String errorCode = "MFA_FACTOR_FAILURE";
        String errorMessage = String.format("%s 인증에 실패했습니다. (남은 시도: %d회)", failedFactorType.name(), Math.max(0, maxAttempts - attempts));
        errorDetails.put("failedFactor", failedFactorType.name());
        errorDetails.put("attemptsMade", attempts);
        errorDetails.put("maxAttempts", maxAttempts);
        errorDetails.put("remainingAttempts", Math.max(0, maxAttempts - attempts));

        if (attempts >= maxAttempts) {
            log.warn("MFA max attempts ({}) reached for factor {}. User: {}. Session: {}. MFA terminated.",
                    maxAttempts, failedFactorType, usernameForLog, factorContext.getMfaSessionId());
            factorContext.changeState(MfaState.MFA_FAILURE_TERMINAL);
            errorCode = "MFA_MAX_ATTEMPTS_EXCEEDED";
            errorMessage = String.format("%s 인증 최대 시도 횟수(%d회)를 초과했습니다. MFA 인증이 종료됩니다.", failedFactorType.name(), maxAttempts);
            errorDetails.put("nextStepUrl", defaultFailureRedirectUrl); // 최종 실패 시 로그인 페이지로
            contextPersistence.deleteContext(request);
        } else {
            factorContext.changeState(MfaState.AWAITING_MFA_FACTOR_SELECTION);
            contextPersistence.saveContext(factorContext, request);
            errorMessage += " 다른 인증 수단을 선택하거나 다시 시도해주세요.";
            errorDetails.put("nextStepUrl", mfaSelectFactorUrl); // Factor 선택 페이지로
        }
        errorDetails.put("mfaSessionId", factorContext.getMfaSessionId()); // mfaSessionId 추가
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, errorCode, errorMessage, request.getRequestURI());
    }

    @Override
    public void onGlobalMfaFailure(HttpServletRequest request,
                                   HttpServletResponse response,
                                   AuthenticationException exception,
                                   @Nullable FactorContext factorContext) throws IOException, ServletException {
        String username = (factorContext != null && factorContext.getUsername() != null) ? factorContext.getUsername() : "UnknownUser";
        String sessionId = (factorContext != null) ? factorContext.getMfaSessionId() : "NoMfaSession";
        log.warn("Global MFA or Primary Auth Failure for user '{}' (MFA Session ID: '{}'). Reason: {}",
                username, sessionId, exception.getMessage());

        if (factorContext != null) {
            factorContext.changeState(MfaState.MFA_FAILURE_TERMINAL);
            contextPersistence.deleteContext(request);
        }
        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("nextStepUrl", defaultFailureRedirectUrl); // 최종 실패 시 로그인 페이지로
        // 만약 1차 인증 실패라면, MfaCapableRestSuccessHandler 등에서 아예 이 핸들러가 호출되기 전에 다른 실패 핸들러가 동작할 수 있음.
        // 이 핸들러는 주로 MFA 플로우 내에서 발생하는 전역적 실패 또는 1차 인증 실패 시 DSL에 의해 명시적으로 연결되었을 때 호출.
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "AUTHENTICATION_FAILED_GLOBAL", "인증 처리 중 오류가 발생했습니다: " + exception.getMessage(), request.getRequestURI());
    }
}
