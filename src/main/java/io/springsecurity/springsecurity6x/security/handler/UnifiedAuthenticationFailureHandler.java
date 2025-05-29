package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.core.session.MfaSessionRepository;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.handler.PlatformAuthenticationFailureHandler.FailureType;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 통합 인증 실패 처리 핸들러
 *
 * 개선사항:
 * - PlatformAuthenticationFailureHandler 지원 추가
 * - 하위 클래스 확장점 제공
 * - response.isCommitted() 체크로 중복 응답 방지
 */
@Slf4j
@RequiredArgsConstructor
public final class UnifiedAuthenticationFailureHandler implements PlatformAuthenticationFailureHandler  {

    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthResponseWriter responseWriter;
    private final AuthContextProperties authContextProperties;
    private final MfaSessionRepository sessionRepository;

    private PlatformAuthenticationFailureHandler delegateHandler;

    /**
     * 사용자 커스텀 핸들러 설정
     */
    public void setDelegateHandler(@Nullable PlatformAuthenticationFailureHandler delegateHandler) {
        this.delegateHandler = delegateHandler;
        if (delegateHandler != null) {
            log.info("Delegate failure handler set: {}", delegateHandler.getClass().getName());
        }
    }

    @Override
    public final void onAuthenticationFailure(HttpServletRequest request,
                                              HttpServletResponse response,
                                              AuthenticationException exception) throws IOException, ServletException {

        // 이미 응답 처리됨
        if (response.isCommitted()) {
            log.warn("Response already committed on authentication failure");
            return;
        }

        long failureStartTime = System.currentTimeMillis();

        FactorContext factorContext = stateMachineIntegrator.loadFactorContextFromRequest(request);
        String usernameForLog = extractUsernameForLogging(factorContext, exception);
        String sessionIdForLog = extractSessionIdForLogging(factorContext);

        log.debug("Processing authentication failure using {} repository for user: {} session: {}",
                sessionRepository.getRepositoryType(), usernameForLog, sessionIdForLog);

        AuthType currentProcessingFactor = (factorContext != null) ? factorContext.getCurrentProcessingFactor() : null;

        if (isMfaFactorFailure(factorContext, currentProcessingFactor)) {
            handleMfaFactorFailure(request, response, exception, factorContext,
                    currentProcessingFactor, usernameForLog, sessionIdForLog);
        } else {
            handlePrimaryAuthOrGlobalMfaFailure(request, response, exception, factorContext,
                    usernameForLog, sessionIdForLog);
        }

        // 보안 감사 로그
        long failureDuration = System.currentTimeMillis() - failureStartTime;
        logSecurityAudit(usernameForLog, sessionIdForLog, currentProcessingFactor,
                exception, failureDuration, getClientInfo(request));
    }

    /**
     * MFA 팩터 검증 실패 처리
     */
    private void handleMfaFactorFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception, FactorContext factorContext,
                                        AuthType currentProcessingFactor, String usernameForLog,
                                        String sessionIdForLog) throws IOException {

        log.warn("MFA Factor Failure using {} repository: Factor '{}' for user '{}' (session ID: '{}') failed. Reason: {}",
                sessionRepository.getRepositoryType(), currentProcessingFactor, usernameForLog, sessionIdForLog, exception.getMessage());

        if (!sessionRepository.existsSession(factorContext.getMfaSessionId())) {
            log.warn("MFA session {} not found in {} repository during factor failure processing",
                    factorContext.getMfaSessionId(), sessionRepository.getRepositoryType());
            handleSessionNotFound(request, response, factorContext, exception);
            return;
        }

        factorContext.recordAttempt(currentProcessingFactor, false,
                "Verification failed: " + exception.getMessage());

        int attempts = factorContext.incrementAttemptCount(currentProcessingFactor);
        RetryPolicy retryPolicy = mfaPolicyProvider.getRetryPolicyForFactor(currentProcessingFactor, factorContext);
        int maxAttempts = (retryPolicy != null) ? retryPolicy.getMaxAttempts() : 3;

        Map<String, Object> errorDetails = buildMfaFailureErrorDetails(factorContext, currentProcessingFactor,
                attempts, maxAttempts);

        if (attempts >= maxAttempts) {
            handleMaxAttemptsExceeded(request, response, exception, factorContext, currentProcessingFactor,
                    usernameForLog, sessionIdForLog, maxAttempts, errorDetails);
        } else {
            handleRetryableMfaFailure(request, response, exception, factorContext, currentProcessingFactor,
                    attempts, maxAttempts, errorDetails);
        }
    }

    /**
     * 최대 시도 횟수 초과 처리
     */
    private void handleMaxAttemptsExceeded(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationException exception, FactorContext factorContext,
                                           AuthType currentProcessingFactor, String usernameForLog,
                                           String sessionIdForLog, int maxAttempts,
                                           Map<String, Object> errorDetails) throws IOException {

        log.warn("MFA max attempts ({}) reached for factor {} using {} repository. User: {}. Session: {}. Terminating MFA.",
                maxAttempts, currentProcessingFactor, sessionRepository.getRepositoryType(), usernameForLog, sessionIdForLog);

        boolean eventAccepted = stateMachineIntegrator.sendEvent(
                MfaEvent.RETRY_LIMIT_EXCEEDED, factorContext, request);

        if (!eventAccepted) {
            log.error("State Machine rejected RETRY_LIMIT_EXCEEDED event for session: {}", sessionIdForLog);
            stateMachineIntegrator.updateStateOnly(factorContext.getMfaSessionId(), MfaState.MFA_FAILED_TERMINAL);
        }

        cleanupSessionUsingRepository(request, response, factorContext.getMfaSessionId());

        String errorCode = "MFA_MAX_ATTEMPTS_EXCEEDED";
        String errorMessage = String.format(
                "%s 인증 최대 시도 횟수(%d회)를 초과했습니다. MFA 인증이 종료됩니다. 다시 로그인해주세요.",
                currentProcessingFactor.name(), maxAttempts);

        String nextStepUrl = request.getContextPath() +
                "/loginForm?error=mfa_locked_" + currentProcessingFactor.name().toLowerCase();

        errorDetails.put("message", errorMessage);
        errorDetails.put("nextStepUrl", nextStepUrl);
        errorDetails.put("terminal", true);
        errorDetails.put("repositoryType", sessionRepository.getRepositoryType());

        // 위임 핸들러 호출
        if (delegateHandler != null && !response.isCommitted()) {
            try {
                delegateHandler.onAuthenticationFailure(request, response, exception, factorContext,
                        FailureType.MFA_MAX_ATTEMPTS_EXCEEDED, errorDetails);
            } catch (Exception e) {
                log.error("Error in delegate failure handler", e);
            }
        }

        // 하위 클래스 훅 호출
        if (!response.isCommitted()) {
            onMfaMaxAttemptsExceeded(request, response, exception, factorContext,
                    currentProcessingFactor, errorDetails);
        }

        // 플랫폼 기본 응답
        if (!response.isCommitted()) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN,
                    errorCode, errorMessage, request.getRequestURI(), errorDetails);
        }
    }

    /**
     * 재시도 가능한 MFA 실패 처리
     */
    private void handleRetryableMfaFailure(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationException exception, FactorContext factorContext,
                                           AuthType currentProcessingFactor, int attempts,
                                           int maxAttempts, Map<String, Object> errorDetails) throws IOException {

        boolean eventAccepted = stateMachineIntegrator.sendEvent(
                MfaEvent.FACTOR_VERIFICATION_FAILED, factorContext, request);

        if (!eventAccepted) {
            log.error("State Machine rejected FACTOR_VERIFICATION_FAILED event for session: {}",
                    factorContext.getMfaSessionId());
        }

        sessionRepository.refreshSession(factorContext.getMfaSessionId());
        stateMachineIntegrator.syncStateWithStateMachine(factorContext, request);

        int remainingAttempts = Math.max(0, maxAttempts - attempts);
        String errorCode = "MFA_FACTOR_VERIFICATION_FAILED";
        String errorMessage = String.format(
                "%s 인증에 실패했습니다. (남은 시도: %d회). 다른 인증 수단을 선택하거나 현재 인증을 다시 시도해주세요.",
                currentProcessingFactor.name(), remainingAttempts);

        // 현재 상태에 따른 다음 URL 결정
        String nextStepUrl;
        if (factorContext.getCurrentState() == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION) {
            // 같은 챌린지 화면으로 (재시도)
            nextStepUrl = determineFactorVerificationUrl(currentProcessingFactor, request);
        } else {
            // 팩터 선택 화면으로
            nextStepUrl = request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl();
        }

        errorDetails.put("message", errorMessage);
        errorDetails.put("nextStepUrl", nextStepUrl);
        errorDetails.put("retryPossibleForCurrentFactor", true);
        errorDetails.put("remainingAttempts", remainingAttempts);
        errorDetails.put("repositoryType", sessionRepository.getRepositoryType());

        // 위임 핸들러 호출
        if (delegateHandler != null && !response.isCommitted()) {
            try {
                delegateHandler.onAuthenticationFailure(request, response, exception, factorContext,
                        FailureType.MFA_FACTOR_FAILED, errorDetails);
            } catch (Exception e) {
                log.error("Error in delegate failure handler", e);
            }
        }

        // 하위 클래스 훅 호출
        if (!response.isCommitted()) {
            onMfaFactorFailure(request, response, exception, factorContext,
                    currentProcessingFactor, errorDetails);
        }

        // 플랫폼 기본 응답
        if (!response.isCommitted()) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED,
                    errorCode, errorMessage, request.getRequestURI(), errorDetails);
        }
    }

    private String determineFactorVerificationUrl(AuthType factorType, HttpServletRequest request) {
        return switch (factorType) {
            case OTT -> request.getContextPath() +
                    authContextProperties.getMfa().getOttFactor().getRequestCodeUiUrl();
            case PASSKEY -> request.getContextPath() +
                    authContextProperties.getMfa().getPasskeyFactor().getRegistrationRequestUrl();
            default -> request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl();
        };
    }

    /**
     * 1차 인증 실패 또는 전역 MFA 실패 처리
     */
    private void handlePrimaryAuthOrGlobalMfaFailure(HttpServletRequest request, HttpServletResponse response,
                                                     AuthenticationException exception, FactorContext factorContext,
                                                     String usernameForLog, String sessionIdForLog)
            throws IOException, ServletException {

        log.warn("Primary Authentication or Global MFA Failure using {} repository for user '{}' (MFA Session ID: '{}'). Reason: {}",
                sessionRepository.getRepositoryType(), usernameForLog, sessionIdForLog, exception.getMessage());

        if (factorContext != null && StringUtils.hasText(factorContext.getMfaSessionId())) {
            try {
                stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, factorContext, request);
            } catch (Exception e) {
                log.warn("Failed to send SYSTEM_ERROR event during cleanup", e);
            }
            cleanupSessionUsingRepository(request, response, factorContext.getMfaSessionId());
        }

        String errorCode = "PRIMARY_AUTH_FAILED";
        String errorMessage = "아이디 또는 비밀번호가 잘못되었습니다.";
        FailureType failureType = FailureType.PRIMARY_AUTH_FAILED;

        if (exception.getMessage() != null && exception.getMessage().contains("MFA")) {
            errorCode = "MFA_GLOBAL_FAILURE";
            errorMessage = "MFA 처리 중 문제가 발생했습니다: " + exception.getMessage();
            failureType = FailureType.MFA_GLOBAL_FAILURE;
        }

        String failureRedirectUrl = request.getContextPath() + "/loginForm?error=" + errorCode.toLowerCase();

        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("message", errorMessage);
        errorDetails.put("nextStepUrl", failureRedirectUrl);
        errorDetails.put("repositoryType", sessionRepository.getRepositoryType());

        // 위임 핸들러 호출
        if (delegateHandler != null && !response.isCommitted()) {
            try {
                delegateHandler.onAuthenticationFailure(request, response, exception,
                        factorContext, failureType, errorDetails);
            } catch (Exception e) {
                log.error("Error in delegate failure handler", e);
            }
        }

        // 하위 클래스 훅 호출
        if (!response.isCommitted()) {
            onPrimaryAuthFailure(request, response, exception, errorDetails);
        }

        // 플랫폼 기본 응답
        if (!response.isCommitted()) {
            if (isApiRequest(request)) {
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED,
                        errorCode, errorMessage, request.getRequestURI(), errorDetails);
            } else {
                response.sendRedirect(failureRedirectUrl);
            }
        }
    }

    /**
     * 세션 미발견 처리
     */
    private void handleSessionNotFound(HttpServletRequest request, HttpServletResponse response,
                                       FactorContext factorContext, AuthenticationException exception)
            throws IOException {
        log.warn("Session not found in {} repository during failure processing: {}",
                sessionRepository.getRepositoryType(), factorContext.getMfaSessionId());

        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("repositoryType", sessionRepository.getRepositoryType());
        errorDetails.put("mfaSessionId", factorContext.getMfaSessionId());

        // 위임 핸들러 호출
        if (delegateHandler != null && !response.isCommitted()) {
            try {
                delegateHandler.onAuthenticationFailure(request, response, exception,
                        factorContext, FailureType.MFA_SESSION_NOT_FOUND, errorDetails);
            } catch (Exception e) {
                log.error("Error in delegate failure handler", e);
            }
        }

        // 하위 클래스 훅 호출
        if (!response.isCommitted()) {
            onMfaSessionNotFound(request, response, exception, factorContext, errorDetails);
        }

        // 플랫폼 기본 응답
        if (!response.isCommitted()) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "SESSION_NOT_FOUND", "MFA 세션을 찾을 수 없습니다.",
                    request.getRequestURI(), errorDetails);
        }
    }

    // ========== 하위 클래스 확장점 ==========

    /**
     * MFA 최대 시도 횟수 초과 시 확장점
     */
    protected void onMfaMaxAttemptsExceeded(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException exception, FactorContext factorContext,
                                            AuthType factor, Map<String, Object> errorDetails)
            throws IOException {
        // 하위 클래스에서 필요시 오버라이드
    }

    /**
     * MFA 팩터 실패 시 확장점
     */
    protected void onMfaFactorFailure(HttpServletRequest request, HttpServletResponse response,
                                      AuthenticationException exception, FactorContext factorContext,
                                      AuthType factor, Map<String, Object> errorDetails)
            throws IOException {
        // 하위 클래스에서 필요시 오버라이드
    }

    /**
     * 1차 인증 실패 시 확장점
     */
    protected void onPrimaryAuthFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception, Map<String, Object> errorDetails)
            throws IOException {
        // 하위 클래스에서 필요시 오버라이드
    }

    /**
     * MFA 세션 미발견 시 확장점
     */
    protected void onMfaSessionNotFound(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception, FactorContext factorContext,
                                        Map<String, Object> errorDetails)
            throws IOException {
        // 하위 클래스에서 필요시 오버라이드
    }

    // ========== 기존 private 메서드들 (변경 없음) ==========

    private void cleanupSessionUsingRepository(HttpServletRequest request, HttpServletResponse response,
                                               String mfaSessionId) {
        try {
            stateMachineIntegrator.releaseStateMachine(mfaSessionId);
            sessionRepository.removeSession(mfaSessionId, request, response);
            log.debug("Session cleanup completed using {} repository for MFA session: {}",
                    sessionRepository.getRepositoryType(), mfaSessionId);
        } catch (Exception e) {
            log.warn("Failed to cleanup session using {} repository: {}",
                    sessionRepository.getRepositoryType(), mfaSessionId, e);
        }
    }

    private Map<String, Object> buildMfaFailureErrorDetails(FactorContext factorContext,
                                                            AuthType currentProcessingFactor,
                                                            int attempts, int maxAttempts) {
        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("mfaSessionId", factorContext.getMfaSessionId());
        errorDetails.put("failedFactor", currentProcessingFactor.name().toUpperCase());
        errorDetails.put("attemptsMade", attempts);
        errorDetails.put("maxAttempts", maxAttempts);
        errorDetails.put("currentState", factorContext.getCurrentState().name());
        errorDetails.put("timestamp", System.currentTimeMillis());
        errorDetails.put("repositoryType", sessionRepository.getRepositoryType());
        errorDetails.put("distributedSync", sessionRepository.supportsDistributedSync());
        return errorDetails;
    }

    private String extractUsernameForLogging(FactorContext factorContext, AuthenticationException exception) {
        if (factorContext != null && StringUtils.hasText(factorContext.getUsername())) {
            return factorContext.getUsername();
        }
        return "UnknownUser";
    }

    private String extractSessionIdForLogging(FactorContext factorContext) {
        if (factorContext != null && StringUtils.hasText(factorContext.getMfaSessionId())) {
            return factorContext.getMfaSessionId();
        }
        return "NoMfaSession";
    }

    private boolean isApiRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");
        if (acceptHeader != null && acceptHeader.contains("application/json")) {
            return true;
        }

        String contentType = request.getContentType();
        if (contentType != null && contentType.contains("application/json")) {
            return true;
        }

        String requestURI = request.getRequestURI();
        return requestURI != null && (requestURI.startsWith("/api/") || requestURI.contains("/api/"));
    }

    private boolean isMfaFactorFailure(FactorContext factorContext, AuthType currentProcessingFactor) {
        if (factorContext == null || currentProcessingFactor == null) {
            return false;
        }

        MfaState currentState = factorContext.getCurrentState();
        return currentState == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ||
                currentState == MfaState.FACTOR_VERIFICATION_PENDING;
    }

    private Map<String, String> getClientInfo(HttpServletRequest request) {
        Map<String, String> clientInfo = new HashMap<>();
        clientInfo.put("userAgent", request.getHeader("User-Agent"));
        clientInfo.put("remoteAddr", request.getRemoteAddr());
        clientInfo.put("xForwardedFor", request.getHeader("X-Forwarded-For"));
        clientInfo.put("referer", request.getHeader("Referer"));
        return clientInfo;
    }

    private void logSecurityAudit(String username, String sessionId, AuthType factorType,
                                  AuthenticationException exception, long duration,
                                  Map<String, String> clientInfo) {

        String factorTypeStr = (factorType != null) ? factorType.name() : "PRIMARY_AUTH";

        log.warn("SECURITY_AUDIT - Authentication Failure: " +
                        "User=[{}], Session=[{}], Factor=[{}], " +
                        "Reason=[{}], Duration=[{}ms], " +
                        "ClientIP=[{}], UserAgent=[{}], XFF=[{}]",
                username, sessionId, factorTypeStr,
                exception.getMessage(), duration,
                clientInfo.get("remoteAddr"),
                clientInfo.get("userAgent"),
                clientInfo.get("xForwardedFor"));
    }
}