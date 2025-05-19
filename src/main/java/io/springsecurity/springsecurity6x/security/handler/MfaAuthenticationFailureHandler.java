package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties; // 추가
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Slf4j
@Component // 스프링 빈으로 등록
@RequiredArgsConstructor
public class MfaAuthenticationFailureHandler implements AuthenticationFailureHandler,
        io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler { // 플랫폼 내부 MfaFailureHandler 인터페이스도 구현

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthResponseWriter responseWriter;
    private final AuthContextProperties authContextProperties; // 실패 시 리다이렉트 URL 위해

    // Spring Security의 AuthenticationFailureHandler 인터페이스 구현
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
            // 현재 처리 중인 Factor가 명확하면 onFactorFailure 호출
            onFactorFailure(request, response, exception, currentProcessingFactor, factorContext);
        } else {
            // Factor 정보가 없으면 전역 MFA 실패로 간주 (예: 1차 인증 실패 후 바로 이 핸들러가 호출된 경우)
            onGlobalMfaFailure(request, response, exception, factorContext);
        }
    }

    // 플랫폼 내부 MfaFailureHandler 인터페이스 구현
    @Override
    public void onFactorFailure(HttpServletRequest request,
                                HttpServletResponse response,
                                AuthenticationException exception,
                                AuthType failedFactorType,
                                FactorContext factorContext) throws IOException { // ServletException 제거 (선택적)
        Assert.notNull(factorContext, "FactorContext cannot be null for onFactorFailure");
        Assert.notNull(failedFactorType, "FailedFactorType cannot be null for onFactorFailure");

        String usernameForLog = factorContext.getUsername() != null ? factorContext.getUsername() : "UnknownUser";
        log.warn("MFA Factor Failure: Factor '{}' for user '{}' (session ID: '{}') failed. Reason: {}",
                failedFactorType, usernameForLog, factorContext.getMfaSessionId(), exception.getMessage());

        factorContext.recordAttempt(failedFactorType, false, "Verification failed: " + exception.getMessage());
        int attempts = factorContext.getAttemptCount(failedFactorType); // getAttemptCount는 null FactorType에 0 반환
        RetryPolicy retryPolicy = mfaPolicyProvider.getRetryPolicyForFactor(failedFactorType, factorContext);
        int maxAttempts = (retryPolicy != null) ? retryPolicy.getMaxAttempts() : 3; // 기본값 3회

        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("mfaSessionId", factorContext.getMfaSessionId());
        errorDetails.put("failedFactor", failedFactorType.name().toUpperCase());
        errorDetails.put("attemptsMade", attempts);
        errorDetails.put("maxAttempts", maxAttempts);
        int remainingAttempts = Math.max(0, maxAttempts - attempts);
        errorDetails.put("remainingAttempts", remainingAttempts);

        String errorCode;
        String errorMessage;
        String nextStepUrl;

        if (attempts >= maxAttempts) {
            log.warn("MFA max attempts ({}) reached for factor {}. User: {}. Session: {}. MFA terminated.",
                    maxAttempts, failedFactorType, usernameForLog, factorContext.getMfaSessionId());
            factorContext.changeState(MfaState.MFA_FAILED_TERMINAL);
            contextPersistence.deleteContext(request); // MFA 세션 완전 종료 및 컨텍스트 삭제

            errorCode = "MFA_MAX_ATTEMPTS_EXCEEDED";
            errorMessage = String.format("%s 인증 최대 시도 횟수(%d회)를 초과했습니다. MFA 인증이 종료됩니다. 다시 로그인해주세요.",
                    failedFactorType.name(), maxAttempts);
            nextStepUrl = request.getContextPath() + "/loginForm?error=mfa_locked"; // 로그인 페이지로
        } else {
            // 재시도 가능: Factor 선택 페이지로 유도하여 다른 Factor를 선택하거나,
            // 동일 Factor를 재시도할 수 있도록 안내 (UI에서 결정).
            // 여기서는 Factor 선택 페이지로 안내.
            factorContext.changeState(MfaState.AWAITING_FACTOR_SELECTION); // 상태 변경
            contextPersistence.saveContext(factorContext, request); // 변경된 컨텍스트 저장

            errorCode = "MFA_FACTOR_VERIFICATION_FAILED";
            errorMessage = String.format("%s 인증에 실패했습니다. (남은 시도: %d회). 다른 인증 수단을 선택하거나 다시 시도해주세요.",
                    failedFactorType.name(), remainingAttempts);
            nextStepUrl = request.getContextPath() + "/mfa/select-factor?error=factor_failed&factor=" + failedFactorType.name().toLowerCase();
        }
        errorDetails.put("message", errorMessage);
        errorDetails.put("nextStepUrl", nextStepUrl); // 클라이언트가 사용할 다음 URL
        // 클라이언트에게 JSON으로 오류 정보 전달
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, errorCode, errorMessage, request.getRequestURI());
    }

    // 플랫폼 내부 MfaFailureHandler 인터페이스 구현
    @Override
    public void onGlobalMfaFailure(HttpServletRequest request,
                                   HttpServletResponse response,
                                   AuthenticationException exception,
                                   @Nullable FactorContext factorContext) throws IOException { // ServletException 제거 (선택적)
        String username = (factorContext != null && factorContext.getUsername() != null) ? factorContext.getUsername() : "UnknownUser";
        String sessionId = (factorContext != null) ? factorContext.getMfaSessionId() : "NoMfaSession";
        log.warn("Global MFA or Primary Auth Failure for user '{}' (MFA Session ID: '{}'). Reason: {}",
                username, sessionId, exception.getMessage());

        if (factorContext != null) {
            factorContext.changeState(MfaState.MFA_FAILED_TERMINAL);
            contextPersistence.deleteContext(request); // 컨텍스트 삭제
        }

        String errorMessage = "인증 처리 중 오류가 발생했습니다: " + exception.getMessage();
        String defaultFailurePage = request.getContextPath() + authContextProperties.getMfa().getFailureUrl(); // 전역 실패 페이지
        if (authContextProperties.getMfa().getFailureUrl().equals("/mfa/failure")) { // 기본 실패 페이지면 로그인 폼으로 유도
            defaultFailurePage = request.getContextPath() + "/loginForm?error=mfa_global_failure";
        }


        // API 요청(JSON 응답 기대)인지, 일반 웹 요청(리다이렉트 기대)인지 구분 필요
        if (request.getHeader("Accept") != null && request.getHeader("Accept").contains("application/json")) {
            Map<String, Object> errorDetails = new HashMap<>();
            errorDetails.put("message", errorMessage);
            errorDetails.put("nextStepUrl", defaultFailurePage);
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "MFA_GLOBAL_FAILURE", errorMessage, request.getRequestURI());
        } else {
            response.sendRedirect(defaultFailurePage);
        }
    }
}
