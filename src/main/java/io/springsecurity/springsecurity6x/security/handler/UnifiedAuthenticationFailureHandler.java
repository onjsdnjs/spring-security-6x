package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.core.session.MfaSessionRepository;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 완전 일원화된 UnifiedAuthenticationFailureHandler
 * - ContextPersistence 완전 제거
 * - MfaStateMachineIntegrator를 통한 State Machine 기반 처리
 * - 보안 강화된 실패 처리 로직
 */
@Slf4j
@RequiredArgsConstructor
public class UnifiedAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthResponseWriter responseWriter;
    private final AuthContextProperties authContextProperties;
    // 추가: Repository 패턴 통합
    private final MfaSessionRepository sessionRepository;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        long failureStartTime = System.currentTimeMillis();

        // 개선: Repository 패턴을 통한 FactorContext 로드 (HttpSession 직접 접근 제거)
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

        // 보안 감사 로그 (Repository 정보 포함)
        long failureDuration = System.currentTimeMillis() - failureStartTime;
        logSecurityAudit(usernameForLog, sessionIdForLog, currentProcessingFactor,
                exception, failureDuration, getClientInfo(request));
    }

    /**
     * 개선: Repository 패턴 통합된 MFA 팩터 검증 실패 처리
     */
    private void handleMfaFactorFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception, FactorContext factorContext,
                                        AuthType currentProcessingFactor, String usernameForLog,
                                        String sessionIdForLog) throws IOException {

        log.warn("MFA Factor Failure using {} repository: Factor '{}' for user '{}' (session ID: '{}') failed. Reason: {}",
                sessionRepository.getRepositoryType(), currentProcessingFactor, usernameForLog, sessionIdForLog, exception.getMessage());

        // 개선: Repository를 통한 세션 검증
        if (!sessionRepository.existsSession(factorContext.getMfaSessionId())) {
            log.warn("MFA session {} not found in {} repository during factor failure processing",
                    factorContext.getMfaSessionId(), sessionRepository.getRepositoryType());
            handleSessionNotFound(request, response, factorContext);
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
            handleMaxAttemptsExceeded(request, response, factorContext, currentProcessingFactor,
                    usernameForLog, sessionIdForLog, maxAttempts, errorDetails);
        } else {
            handleRetryableMfaFailure(request, response, factorContext, currentProcessingFactor,
                    attempts, maxAttempts, errorDetails);
        }
    }

    /**
     * 개선: Repository 패턴 통합된 최대 시도 횟수 초과 처리
     */
    private void handleMaxAttemptsExceeded(HttpServletRequest request, HttpServletResponse response,
                                           FactorContext factorContext, AuthType currentProcessingFactor,
                                           String usernameForLog, String sessionIdForLog, int maxAttempts,
                                           Map<String, Object> errorDetails) throws IOException {

        log.warn("MFA max attempts ({}) reached for factor {} using {} repository. User: {}. Session: {}. Terminating MFA.",
                maxAttempts, currentProcessingFactor, sessionRepository.getRepositoryType(), usernameForLog, sessionIdForLog);

        boolean eventAccepted = stateMachineIntegrator.sendEvent(
                MfaEvent.RETRY_LIMIT_EXCEEDED, factorContext, request);

        if (!eventAccepted) {
            log.error("State Machine rejected RETRY_LIMIT_EXCEEDED event for session: {}", sessionIdForLog);
            stateMachineIntegrator.updateStateOnly(factorContext.getMfaSessionId(), MfaState.MFA_FAILED_TERMINAL);
        }

        // 개선: Repository를 통한 세션 정리
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
        errorDetails.put("repositoryType", sessionRepository.getRepositoryType()); // 추가

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN,
                errorCode, errorMessage, request.getRequestURI(), errorDetails);
    }

    /**
     * 개선: Repository 패턴 통합된 재시도 가능한 MFA 실패 처리
     */
    private void handleRetryableMfaFailure(HttpServletRequest request, HttpServletResponse response,
                                           FactorContext factorContext, AuthType currentProcessingFactor,
                                           int attempts, int maxAttempts, Map<String, Object> errorDetails)
            throws IOException {

        boolean eventAccepted = stateMachineIntegrator.sendEvent(
                MfaEvent.FACTOR_VERIFICATION_FAILED, factorContext, request);

        if (!eventAccepted) {
            log.error("State Machine rejected FACTOR_VERIFICATION_FAILED event for session: {}",
                    factorContext.getMfaSessionId());
            stateMachineIntegrator.updateStateOnly(factorContext.getMfaSessionId(),
                    MfaState.AWAITING_FACTOR_SELECTION);
        }

        // 개선: Repository를 통한 세션 갱신
        sessionRepository.refreshSession(factorContext.getMfaSessionId());

        stateMachineIntegrator.syncStateWithStateMachine(factorContext, request);

        int remainingAttempts = Math.max(0, maxAttempts - attempts);
        String errorCode = "MFA_FACTOR_VERIFICATION_FAILED";
        String errorMessage = String.format(
                "%s 인증에 실패했습니다. (남은 시도: %d회). 다른 인증 수단을 선택하거나 현재 인증을 다시 시도해주세요.",
                currentProcessingFactor.name(), remainingAttempts);

        String nextStepUrl = request.getContextPath() + authContextProperties.getMfa().getInitiateUrl();

        errorDetails.put("message", errorMessage);
        errorDetails.put("nextStepUrl", nextStepUrl);
        errorDetails.put("retryPossibleForCurrentFactor", true);
        errorDetails.put("remainingAttempts", remainingAttempts);
        errorDetails.put("repositoryType", sessionRepository.getRepositoryType()); // 추가

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED,
                errorCode, errorMessage, request.getRequestURI(), errorDetails);
    }

    /**
     * 개선: Repository 패턴 통합된 1차 인증 실패 또는 전역 MFA 실패 처리
     */
    private void handlePrimaryAuthOrGlobalMfaFailure(HttpServletRequest request, HttpServletResponse response,
                                                     AuthenticationException exception, FactorContext factorContext,
                                                     String usernameForLog, String sessionIdForLog)
            throws IOException, ServletException {

        log.warn("Primary Authentication or Global MFA Failure using {} repository for user '{}' (MFA Session ID: '{}'). Reason: {}",
                sessionRepository.getRepositoryType(), usernameForLog, sessionIdForLog, exception.getMessage());

        // 개선: Repository 패턴을 통한 세션 정리
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

        if (exception.getMessage() != null && exception.getMessage().contains("MFA")) {
            errorCode = "MFA_GLOBAL_FAILURE";
            errorMessage = "MFA 처리 중 문제가 발생했습니다: " + exception.getMessage();
        }

        String failureRedirectUrl = request.getContextPath() + "/loginForm?error=" + errorCode.toLowerCase();

        if (isApiRequest(request)) {
            Map<String, Object> errorDetails = new HashMap<>();
            errorDetails.put("message", errorMessage);
            errorDetails.put("nextStepUrl", failureRedirectUrl);
            errorDetails.put("repositoryType", sessionRepository.getRepositoryType()); // 추가

            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED,
                    errorCode, errorMessage, request.getRequestURI(), errorDetails);
        } else {
            response.sendRedirect(failureRedirectUrl);
        }
    }

    /**
     * 개선: Repository 패턴을 통한 세션 정리 (HttpSession 직접 접근 제거)
     */
    private void cleanupSessionUsingRepository(HttpServletRequest request, HttpServletResponse response, String mfaSessionId) {
        try {
            stateMachineIntegrator.releaseStateMachine(mfaSessionId);
            sessionRepository.removeSession(mfaSessionId, request, response);

            // HttpSession 에서도 정리 (호환성 유지)
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.removeAttribute("MFA_SESSION_ID");
            }

            log.debug("Session cleanup completed using {} repository for MFA session: {}",
                    sessionRepository.getRepositoryType(), mfaSessionId);
        } catch (Exception e) {
            log.warn("Failed to cleanup session using {} repository: {}",
                    sessionRepository.getRepositoryType(), mfaSessionId, e);
        }
    }

    /**
     * 개선: Repository 패턴을 통한 세션 미발견 처리
     */
    private void handleSessionNotFound(HttpServletRequest request, HttpServletResponse response,
                                       FactorContext factorContext) throws IOException {
        log.warn("Session not found in {} repository during failure processing: {}",
                sessionRepository.getRepositoryType(), factorContext.getMfaSessionId());

        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("repositoryType", sessionRepository.getRepositoryType());
        errorDetails.put("mfaSessionId", factorContext.getMfaSessionId());

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                "SESSION_NOT_FOUND", "MFA 세션을 찾을 수 없습니다.", request.getRequestURI(), errorDetails);
    }

    /**
     * 개선: Repository 정보를 포함한 MFA 실패 에러 상세 정보 구성
     */
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
        // 개선: Repository 정보 추가
        errorDetails.put("repositoryType", sessionRepository.getRepositoryType());
        errorDetails.put("distributedSync", sessionRepository.supportsDistributedSync());

        return errorDetails;
    }

    /**
     * 로깅용 사용자명 추출
     */
    private String extractUsernameForLogging(FactorContext factorContext, AuthenticationException exception) {
        if (factorContext != null && StringUtils.hasText(factorContext.getUsername())) {
            return factorContext.getUsername();
        }

        // Exception에서 사용자명 추출 시도
        if (exception.getAuthenticationRequest() != null && exception.getAuthenticationRequest().getName() != null) {
            return exception.getAuthenticationRequest().getName();
        }

        return "UnknownUser";
    }

    /**
     * 로깅용 세션 ID 추출
     */
    private String extractSessionIdForLogging(FactorContext factorContext) {
        if (factorContext != null && StringUtils.hasText(factorContext.getMfaSessionId())) {
            return factorContext.getMfaSessionId();
        }
        return "NoMfaSession";
    }

    /**
     * API 요청 여부 확인 (강화)
     */
    private boolean isApiRequest(HttpServletRequest request) {
        // Accept 헤더 확인
        String acceptHeader = request.getHeader("Accept");
        if (acceptHeader != null && acceptHeader.contains("application/json")) {
            return true;
        }

        // Content-Type 헤더 확인
        String contentType = request.getContentType();
        if (contentType != null && contentType.contains("application/json")) {
            return true;
        }

        // URL 패턴으로 확인
        String requestURI = request.getRequestURI();
        return requestURI != null && (requestURI.startsWith("/api/") || requestURI.contains("/api/"));
    }

    /**
     * MFA 팩터 실패인지 확인
     */
    private boolean isMfaFactorFailure(FactorContext factorContext, AuthType currentProcessingFactor) {
        if (factorContext == null || currentProcessingFactor == null) {
            return false;
        }

        MfaState currentState = factorContext.getCurrentState();
        return currentState == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ||
                currentState == MfaState.FACTOR_VERIFICATION_PENDING ||
                currentState == MfaState.FACTOR_VERIFICATION_IN_PROGRESS;
    }

    /**
     * 클라이언트 정보 수집 (보안 감사용)
     */
    private Map<String, String> getClientInfo(HttpServletRequest request) {
        Map<String, String> clientInfo = new HashMap<>();
        clientInfo.put("userAgent", request.getHeader("User-Agent"));
        clientInfo.put("remoteAddr", request.getRemoteAddr());
        clientInfo.put("xForwardedFor", request.getHeader("X-Forwarded-For"));
        clientInfo.put("referer", request.getHeader("Referer"));
        return clientInfo;
    }

    /**
     * 보안 감사 로그 (강화)
     */
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