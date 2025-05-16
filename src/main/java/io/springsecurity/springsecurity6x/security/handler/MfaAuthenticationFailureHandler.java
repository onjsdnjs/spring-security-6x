package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.Assert;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class MfaAuthenticationFailureHandler implements AuthenticationFailureHandler, io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthResponseWriter responseWriter; // 추가

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

    // 사용자 정의 MfaFailureHandler 인터페이스 메서드
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

        String errorCode = "MFA_FACTOR_FAILURE";
        String errorMessage = String.format("%s 인증에 실패했습니다. (시도: %d/%d)", failedFactorType.name(), attempts, maxAttempts);
        int status = HttpServletResponse.SC_UNAUTHORIZED;

        if (attempts >= maxAttempts) {
            log.warn("MFA max attempts ({}) reached for factor {}. User: {}. Session: {}. MFA terminated.",
                    maxAttempts, failedFactorType, usernameForLog, factorContext.getMfaSessionId());
            factorContext.changeState(MfaState.MFA_FAILURE_TERMINAL);
            errorCode = "MFA_MAX_ATTEMPTS_EXCEEDED";
            errorMessage = String.format("%s 인증 최대 시도 횟수(%d회)를 초과했습니다. MFA 인증이 종료됩니다.", failedFactorType.name(), maxAttempts);
            contextPersistence.deleteContext(request);
        } else {
            factorContext.changeState(MfaState.AWAITING_MFA_FACTOR_SELECTION); // 재시도 가능 시 선택 화면으로
            contextPersistence.saveContext(factorContext, request);
            errorMessage += String.format(" %d회 더 시도할 수 있습니다. 다른 인증 수단을 선택하거나 다시 시도해주세요.", maxAttempts - attempts);
            // 클라이언트에게 다음 단계 URL을 알려줄 수도 있음
            // responseDetails.put("nextStepUrl", "/mfa/select-factor");
        }
        responseWriter.writeErrorResponse(response, status, errorCode, errorMessage, request.getRequestURI());
    }

    @Override
    public void onGlobalMfaFailure(HttpServletRequest request,
                                   HttpServletResponse response,
                                   AuthenticationException exception,
                                   @Nullable FactorContext factorContext) throws IOException, ServletException {
        String username = (factorContext != null && factorContext.getUsername() != null) ? factorContext.getUsername() : "UnknownUser";
        String sessionId = (factorContext != null) ? factorContext.getMfaSessionId() : "NoMfaSession";
        log.warn("Global MFA Failure for user '{}' (MFA Session ID: '{}'). Reason: {}",
                username, sessionId, exception.getMessage());

        if (factorContext != null) {
            factorContext.changeState(MfaState.MFA_FAILURE_TERMINAL);
            contextPersistence.deleteContext(request);
        }
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "MFA_GLOBAL_FAILURE", "MFA 인증 처리 중 오류가 발생했습니다: " + exception.getMessage(), request.getRequestURI());
    }
}
