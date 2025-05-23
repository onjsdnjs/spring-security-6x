package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.utils.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class UnifiedAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthResponseWriter responseWriter;
    private final AuthContextProperties authContextProperties;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        FactorContext factorContext = contextPersistence.contextLoad(request);
        String usernameForLog = "UnknownUser";
        String sessionIdForLog = "NoMfaSession";

        if (factorContext != null) {
            usernameForLog = factorContext.getUsername() != null ? factorContext.getUsername() : usernameForLog;
            sessionIdForLog = factorContext.getMfaSessionId() != null ? factorContext.getMfaSessionId() : sessionIdForLog;
        }

        // 현재 처리 중인 Factor가 있는지 확인 (MFA 단계 중 실패인지, 1차 인증 실패인지 구분)
        AuthType currentProcessingFactor = (factorContext != null) ? factorContext.getCurrentProcessingFactor() : null;

        if (factorContext != null && currentProcessingFactor != null &&
                (factorContext.getCurrentState() == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ||
                        factorContext.getCurrentState() == MfaState.FACTOR_VERIFICATION_PENDING) ) {
            // 2차 인증 Factor 처리 중 실패
            log.warn("MFA Factor Failure: Factor '{}' for user '{}' (session ID: '{}') failed. Reason: {}",
                    currentProcessingFactor, usernameForLog, sessionIdForLog, exception.getMessage());

            factorContext.recordAttempt(currentProcessingFactor, false, "Verification failed: " + exception.getMessage());
            int attempts = factorContext.incrementAttemptCount(currentProcessingFactor); // 시도 횟수 여기서 증가
            RetryPolicy retryPolicy = mfaPolicyProvider.getRetryPolicyForFactor(currentProcessingFactor, factorContext);
            int maxAttempts = (retryPolicy != null) ? retryPolicy.getMaxAttempts() : 3;

            Map<String, Object> errorDetails = new HashMap<>();
            errorDetails.put("mfaSessionId", factorContext.getMfaSessionId());
            errorDetails.put("failedFactor", currentProcessingFactor.name().toUpperCase());
            errorDetails.put("attemptsMade", attempts);
            errorDetails.put("maxAttempts", maxAttempts);
            int remainingAttempts = Math.max(0, maxAttempts - attempts);
            errorDetails.put("remainingAttempts", remainingAttempts);

            String errorCode;
            String errorMessage;
            String nextStepUrl = null; // 클라이언트에게 다음 단계를 안내할 URL

            if (attempts >= maxAttempts) {
                log.warn("MFA max attempts ({}) reached for factor {}. User: {}. Session: {}. Terminating MFA.",
                        maxAttempts, currentProcessingFactor, usernameForLog, sessionIdForLog);
                factorContext.changeState(MfaState.MFA_FAILED_TERMINAL);
                factorContext.setCurrentStepId(null); // 초기화
                factorContext.setCurrentProcessingFactor(null);
                factorContext.setCurrentFactorOptions(null);
                contextPersistence.deleteContext(request);

                errorCode = "MFA_MAX_ATTEMPTS_EXCEEDED";
                errorMessage = String.format("%s 인증 최대 시도 횟수(%d회)를 초과했습니다. MFA 인증이 종료됩니다. 다시 로그인해주세요.",
                        currentProcessingFactor.name(), maxAttempts);
                nextStepUrl = request.getContextPath() + "/loginForm?error=mfa_locked_" + currentProcessingFactor.name().toLowerCase();
            } else {
                // 재시도 가능: Factor 선택 페이지로 유도 (다른 Factor 선택 또는 현재 Factor 재시도 UI는 클라이언트가 결정)
                factorContext.changeState(MfaState.AWAITING_FACTOR_SELECTION); // 실패 시 다시 선택으로
                factorContext.setCurrentStepId(null); // 초기화
                factorContext.setCurrentProcessingFactor(null);
                factorContext.setCurrentFactorOptions(null);
                contextPersistence.saveContext(factorContext, request);

                errorCode = "MFA_FACTOR_VERIFICATION_FAILED";
                errorMessage = String.format("%s 인증에 실패했습니다. (남은 시도: %d회). 다른 인증 수단을 선택하거나 현재 인증을 다시 시도해주세요.",
                        currentProcessingFactor.name(), remainingAttempts);
                nextStepUrl = request.getContextPath() + authContextProperties.getMfa().getInitiateUrl(); // Factor 선택 페이지
                errorDetails.put("retryPossibleForCurrentFactor", true);
            }
            errorDetails.put("message", errorMessage);
            errorDetails.put("nextStepUrl", nextStepUrl);

            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, errorCode, errorMessage, request.getRequestURI(), errorDetails);

        } else {
            // 1차 인증 실패 또는 Factor 정보 없는 전역 MFA 실패
            log.warn("Primary Authentication or Global MFA Failure for user '{}' (MFA Session ID: '{}'). Reason: {}",
                    usernameForLog, sessionIdForLog, exception.getMessage());

            if (factorContext != null) { // 컨텍스트가 있다면 정리
                factorContext.changeState(MfaState.MFA_FAILED_TERMINAL);
                contextPersistence.deleteContext(request);
            }

            String errorCode = "PRIMARY_AUTH_FAILED";
            String errorMessage = "아이디 또는 비밀번호가 잘못되었습니다.";
            if (exception.getMessage() != null && exception.getMessage().contains("MFA")) { // 좀 더 구체적인 메시지
                errorCode = "MFA_GLOBAL_FAILURE";
                errorMessage = "MFA 처리 중 문제가 발생했습니다: " + exception.getMessage();
            }
            String failureRedirectUrl = request.getContextPath() + "/loginForm?error=" + errorCode.toLowerCase();

            if (isApiRequest(request)) {
                Map<String, Object> errorDetails = new HashMap<>();
                errorDetails.put("message", errorMessage);
                errorDetails.put("nextStepUrl", failureRedirectUrl);
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, errorCode, errorMessage, request.getRequestURI(), errorDetails);
            } else {
                // Spring Security의 기본 SimpleUrlAuthenticationFailureHandler 동작과 유사하게 리다이렉트
                response.sendRedirect(failureRedirectUrl);
            }
        }
    }

    private boolean isApiRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");
        return acceptHeader != null && acceptHeader.contains("application/json");
    }
}
