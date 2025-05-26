package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.utils.AuthResponseWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

    private final MfaStateMachineIntegrator stateMachineIntegrator; // 완전 일원화
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthResponseWriter responseWriter;
    private final AuthContextProperties authContextProperties;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        long failureStartTime = System.currentTimeMillis();

        // 완전 일원화: State Machine 통합자에서 FactorContext 로드
        FactorContext factorContext = stateMachineIntegrator.loadFactorContextFromRequest(request);

        String usernameForLog = extractUsernameForLogging(factorContext, exception);
        String sessionIdForLog = extractSessionIdForLogging(factorContext);

        // MFA 단계 중 실패인지, 1차 인증 실패인지 구분
        AuthType currentProcessingFactor = (factorContext != null) ? factorContext.getCurrentProcessingFactor() : null;

        if (isMfaFactorFailure(factorContext, currentProcessingFactor)) {
            // MFA 팩터 검증 실패 처리
            handleMfaFactorFailure(request, response, exception, factorContext,
                    currentProcessingFactor, usernameForLog, sessionIdForLog);
        } else {
            // 1차 인증 실패 또는 전역 MFA 실패 처리
            handlePrimaryAuthOrGlobalMfaFailure(request, response, exception, factorContext,
                    usernameForLog, sessionIdForLog);
        }

        // 보안 감사 로그 (타이밍 정보 포함)
        long failureDuration = System.currentTimeMillis() - failureStartTime;
        logSecurityAudit(usernameForLog, sessionIdForLog, currentProcessingFactor,
                exception, failureDuration, getClientInfo(request));
    }

    /**
     * 완전 일원화: MFA 팩터 검증 실패 처리
     */
    private void handleMfaFactorFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception, FactorContext factorContext,
                                        AuthType currentProcessingFactor, String usernameForLog,
                                        String sessionIdForLog) throws IOException {

        log.warn("MFA Factor Failure: Factor '{}' for user '{}' (session ID: '{}') failed. Reason: {}",
                currentProcessingFactor, usernameForLog, sessionIdForLog, exception.getMessage());

        // 실패 시도 기록 (State Machine에 자동 저장됨)
        factorContext.recordAttempt(currentProcessingFactor, false,
                "Verification failed: " + exception.getMessage());

        int attempts = factorContext.incrementAttemptCount(currentProcessingFactor);
        RetryPolicy retryPolicy = mfaPolicyProvider.getRetryPolicyForFactor(currentProcessingFactor, factorContext);
        int maxAttempts = (retryPolicy != null) ? retryPolicy.getMaxAttempts() : 3;

        // 에러 상세 정보 구성
        Map<String, Object> errorDetails = buildMfaFailureErrorDetails(factorContext, currentProcessingFactor,
                attempts, maxAttempts);

        if (attempts >= maxAttempts) {
            // 최대 시도 횟수 초과 - 터미널 상태로 전환
            handleMaxAttemptsExceeded(request, response, factorContext, currentProcessingFactor,
                    usernameForLog, sessionIdForLog, maxAttempts, errorDetails);
        } else {
            // 재시도 가능 - 팩터 선택으로 돌아가기
            handleRetryableMfaFailure(request, response, factorContext, currentProcessingFactor,
                    attempts, maxAttempts, errorDetails);
        }
    }

    /**
     * 완전 일원화: 최대 시도 횟수 초과 처리
     */
    private void handleMaxAttemptsExceeded(HttpServletRequest request, HttpServletResponse response,
                                           FactorContext factorContext, AuthType currentProcessingFactor,
                                           String usernameForLog, String sessionIdForLog, int maxAttempts,
                                           Map<String, Object> errorDetails) throws IOException {

        log.warn("MFA max attempts ({}) reached for factor {}. User: {}. Session: {}. Terminating MFA.",
                maxAttempts, currentProcessingFactor, usernameForLog, sessionIdForLog);

        // 완전 일원화: State Machine 이벤트로 상태 전환
        boolean eventAccepted = stateMachineIntegrator.sendEvent(
                MfaEvent.RETRY_LIMIT_EXCEEDED, factorContext, request);

        if (!eventAccepted) {
            log.error("State Machine rejected RETRY_LIMIT_EXCEEDED event for session: {}", sessionIdForLog);
            // Fallback: 강제로 터미널 상태 설정
            stateMachineIntegrator.updateStateOnly(factorContext.getMfaSessionId(), MfaState.MFA_FAILED_TERMINAL);
        }

        // 완전 일원화: State Machine 세션 정리
        stateMachineIntegrator.cleanupSession(request);

        String errorCode = "MFA_MAX_ATTEMPTS_EXCEEDED";
        String errorMessage = String.format(
                "%s 인증 최대 시도 횟수(%d회)를 초과했습니다. MFA 인증이 종료됩니다. 다시 로그인해주세요.",
                currentProcessingFactor.name(), maxAttempts);

        String nextStepUrl = request.getContextPath() +
                "/loginForm?error=mfa_locked_" + currentProcessingFactor.name().toLowerCase();

        errorDetails.put("message", errorMessage);
        errorDetails.put("nextStepUrl", nextStepUrl);
        errorDetails.put("terminal", true);
        errorDetails.put("storageType", "UNIFIED_STATE_MACHINE");

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN,
                errorCode, errorMessage, request.getRequestURI(), errorDetails);
    }

    /**
     * 완전 일원화: 재시도 가능한 MFA 실패 처리
     */
    private void handleRetryableMfaFailure(HttpServletRequest request, HttpServletResponse response,
                                           FactorContext factorContext, AuthType currentProcessingFactor,
                                           int attempts, int maxAttempts, Map<String, Object> errorDetails)
            throws IOException {

        // 완전 일원화: State Machine 이벤트로 상태 전환
        boolean eventAccepted = stateMachineIntegrator.sendEvent(
                MfaEvent.FACTOR_VERIFICATION_FAILED, factorContext, request);

        if (!eventAccepted) {
            log.error("State Machine rejected FACTOR_VERIFICATION_FAILED event for session: {}",
                    factorContext.getMfaSessionId());
            // Fallback: 팩터 선택 상태로 직접 전환
            stateMachineIntegrator.updateStateOnly(factorContext.getMfaSessionId(),
                    MfaState.AWAITING_FACTOR_SELECTION);
        }

        // State Machine과 동기화
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
        errorDetails.put("storageType", "UNIFIED_STATE_MACHINE");

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED,
                errorCode, errorMessage, request.getRequestURI(), errorDetails);
    }

    /**
     * 완전 일원화: 1차 인증 실패 또는 전역 MFA 실패 처리
     */
    private void handlePrimaryAuthOrGlobalMfaFailure(HttpServletRequest request, HttpServletResponse response,
                                                     AuthenticationException exception, FactorContext factorContext,
                                                     String usernameForLog, String sessionIdForLog)
            throws IOException, ServletException {

        log.warn("Primary Authentication or Global MFA Failure for user '{}' (MFA Session ID: '{}'). Reason: {}",
                usernameForLog, sessionIdForLog, exception.getMessage());

        // 완전 일원화: State Machine이 있다면 정리
        if (factorContext != null && StringUtils.hasText(factorContext.getMfaSessionId())) {
            // State Machine 이벤트로 터미널 상태 전환
            try {
                stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, factorContext, request);
            } catch (Exception e) {
                log.warn("Failed to send SYSTEM_ERROR event during cleanup", e);
            }

            // 완전 일원화: State Machine 세션 정리
            stateMachineIntegrator.cleanupSession(request);
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
            errorDetails.put("storageType", "UNIFIED_STATE_MACHINE");

            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED,
                    errorCode, errorMessage, request.getRequestURI(), errorDetails);
        } else {
            // 웹 요청: 리다이렉트
            response.sendRedirect(failureRedirectUrl);
        }
    }

    // === 유틸리티 메서드들 ===

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
     * MFA 실패 에러 상세 정보 구성
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
        errorDetails.put("storageType", "UNIFIED_STATE_MACHINE");

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