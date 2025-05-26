package io.springsecurity.springsecurity6x.security.filter.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.filter.matcher.MfaRequestType;
import io.springsecurity.springsecurity6x.security.filter.matcher.MfaUrlMatcher;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.core.service.MfaStateMachineService;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 완전 일원화된 StateMachineAwareMfaRequestHandler
 * - ContextPersistence 완전 제거
 * - MfaStateMachineService만 사용
 * - State Machine 기반 요청 처리
 */
@Slf4j
public class StateMachineAwareMfaRequestHandler implements MfaRequestHandler {

    // ContextPersistence 완전 제거
    private final MfaStateMachineService stateMachineService; // State Machine Service만 사용
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final MfaUrlMatcher urlMatcher;
    private final MfaStateMachineIntegrator stateMachineIntegrator;

    public StateMachineAwareMfaRequestHandler(MfaStateMachineService stateMachineService, // ContextPersistence 대신 사용
                                              MfaPolicyProvider mfaPolicyProvider,
                                              AuthContextProperties authContextProperties,
                                              AuthResponseWriter responseWriter,
                                              ApplicationContext applicationContext,
                                              MfaUrlMatcher urlMatcher,
                                              MfaStateMachineIntegrator stateMachineIntegrator) {
        this.stateMachineService = stateMachineService;
        this.mfaPolicyProvider = mfaPolicyProvider;
        this.authContextProperties = authContextProperties;
        this.responseWriter = responseWriter;
        this.applicationContext = applicationContext;
        this.urlMatcher = urlMatcher;
        this.stateMachineIntegrator = stateMachineIntegrator;

        log.info("StateMachineAwareMfaRequestHandler initialized with unified State Machine Service");
    }

    @Override
    public void handleRequest(MfaRequestType requestType, HttpServletRequest request,
                              HttpServletResponse response, FactorContext context,
                              FilterChain filterChain) throws ServletException, IOException {

        String sessionId = context.getMfaSessionId();
        log.debug("Handling {} request for session: {} via unified State Machine", requestType, sessionId);

        // State Machine과 동기화
        stateMachineIntegrator.syncStateWithStateMachine(context, request);

        switch (requestType) {
            case FACTOR_SELECTION:
                handleFactorSelection(request, response, context);
                break;

            case CHALLENGE_INITIATION:
                handleChallengeInitiation(request, response, context);
                break;

            case FACTOR_VERIFICATION:
                handleFactorVerification(request, response, context, filterChain);
                break;

            case STATUS_CHECK:
                handleStatusCheck(request, response, context);
                break;

            case SESSION_REFRESH:
                handleSessionRefresh(request, response, context);
                break;

            case CANCEL_MFA:
                handleCancelMfa(request, response, context);
                break;

            default:
                handleUnsupportedRequest(request, response, context, requestType);
                break;
        }
    }

    @Override
    public void handleTerminalContext(HttpServletRequest request, HttpServletResponse response,
                                      FactorContext context) throws ServletException, IOException {
        String sessionId = context.getMfaSessionId();
        MfaState currentState = context.getCurrentState();

        log.info("Handling terminal context for session: {}, state: {}", sessionId, currentState);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("mfaSessionId", sessionId);
        responseBody.put("currentState", currentState.name());
        responseBody.put("terminal", true);

        switch (currentState) {
            case MFA_SUCCESSFUL:
            case ALL_FACTORS_COMPLETED:
                responseBody.put("status", "MFA_COMPLETED");
                responseBody.put("message", "MFA 인증이 완료되었습니다.");
                responseBody.put("redirectUrl", request.getContextPath() + "/home");
                responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
                break;

            case MFA_FAILED_TERMINAL:
            case MFA_RETRY_LIMIT_EXCEEDED:
                responseBody.put("status", "MFA_FAILED");
                responseBody.put("message", "MFA 인증이 실패했습니다.");
                responseBody.put("redirectUrl", request.getContextPath() + "/loginForm");
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN,
                        "MFA_FAILED", "MFA 인증 실패", request.getRequestURI(), responseBody);
                break;

            case MFA_SESSION_EXPIRED:
                responseBody.put("status", "SESSION_EXPIRED");
                responseBody.put("message", "MFA 세션이 만료되었습니다.");
                responseBody.put("redirectUrl", request.getContextPath() + "/loginForm");
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN,
                        "SESSION_EXPIRED", "세션 만료", request.getRequestURI(), responseBody);
                break;

            case MFA_CANCELLED:
                responseBody.put("status", "MFA_CANCELLED");
                responseBody.put("message", "사용자에 의해 MFA가 취소되었습니다.");
                responseBody.put("redirectUrl", request.getContextPath() + "/loginForm");
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        "MFA_CANCELLED", "MFA 취소", request.getRequestURI(), responseBody);
                break;

            default:
                responseBody.put("status", "UNKNOWN_TERMINAL_STATE");
                responseBody.put("message", "알 수 없는 터미널 상태입니다.");
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "UNKNOWN_STATE", "알 수 없는 상태", request.getRequestURI(), responseBody);
                break;
        }

        // 터미널 상태 도달 시 State Machine 정리
        stateMachineIntegrator.cleanupSession(request);
    }

    @Override
    public void handleGenericError(HttpServletRequest request, HttpServletResponse response,
                                   FactorContext context, Exception error) throws ServletException, IOException {
        String sessionId = context != null ? context.getMfaSessionId() : "unknown";
        log.error("Generic error in MFA request handling for session: {}", sessionId, error);

        // State Machine에 시스템 에러 이벤트 전송
        if (context != null) {
            stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, context, request);
        }

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "MFA_PROCESSING_ERROR");
        errorResponse.put("message", "MFA 처리 중 오류가 발생했습니다.");
        if (context != null) {
            errorResponse.put("mfaSessionId", context.getMfaSessionId());
        }

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "MFA_PROCESSING_ERROR", error.getMessage(), request.getRequestURI(), errorResponse);
    }

    // === 개별 요청 처리 메서드들 ===

    /**
     * 팩터 선택 처리
     */
    private void handleFactorSelection(HttpServletRequest request, HttpServletResponse response,
                                       FactorContext context) throws IOException {
        String sessionId = context.getMfaSessionId();
        log.debug("Handling factor selection for session: {}", sessionId);

        // 팩터 선택 가능한 상태인지 확인
        if (context.getCurrentState() != MfaState.AWAITING_FACTOR_SELECTION) {
            log.warn("Factor selection requested in invalid state: {} for session: {}",
                    context.getCurrentState(), sessionId);

            Map<String, Object> errorResponse = createErrorResponse(context, "INVALID_STATE_FOR_SELECTION",
                    "팩터 선택이 불가능한 상태입니다.");
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "INVALID_STATE", "Invalid state for factor selection", request.getRequestURI(), errorResponse);
            return;
        }

        // 선택된 팩터 추출
        String selectedFactor = request.getParameter("factor");
        if (selectedFactor == null || selectedFactor.trim().isEmpty()) {
            Map<String, Object> errorResponse = createErrorResponse(context, "MISSING_FACTOR_PARAMETER",
                    "선택할 팩터를 지정해주세요.");
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "MISSING_PARAMETER", "Missing factor parameter", request.getRequestURI(), errorResponse);
            return;
        }

        // 팩터 선택 이벤트 전송
        boolean accepted = stateMachineIntegrator.sendEvent(MfaEvent.FACTOR_SELECTED, context, request);

        if (accepted) {
            // 정책 제공자를 통해 다음 단계 결정
            mfaPolicyProvider.determineNextFactorToProcess(context);

            Map<String, Object> successResponse = createSuccessResponse(context, "FACTOR_SELECTED",
                    "팩터가 선택되었습니다.");
            successResponse.put("selectedFactor", selectedFactor);
            successResponse.put("nextStepUrl", determineNextStepUrl(context, request));

            responseWriter.writeSuccessResponse(response, successResponse, HttpServletResponse.SC_OK);
        } else {
            Map<String, Object> errorResponse = createErrorResponse(context, "FACTOR_SELECTION_REJECTED",
                    "팩터 선택이 거부되었습니다.");
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "SELECTION_REJECTED", "Factor selection rejected", request.getRequestURI(), errorResponse);
        }
    }

    /**
     * 챌린지 시작 처리
     */
    private void handleChallengeInitiation(HttpServletRequest request, HttpServletResponse response,
                                           FactorContext context) throws IOException {
        String sessionId = context.getMfaSessionId();
        log.debug("Handling challenge initiation for session: {}", sessionId);

        // 챌린지 시작 가능한 상태인지 확인
        if (context.getCurrentState() != MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION) {
            log.warn("Challenge initiation requested in invalid state: {} for session: {}",
                    context.getCurrentState(), sessionId);

            Map<String, Object> errorResponse = createErrorResponse(context, "INVALID_STATE_FOR_CHALLENGE",
                    "챌린지 시작이 불가능한 상태입니다.");
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "INVALID_STATE", "Invalid state for challenge initiation", request.getRequestURI(), errorResponse);
            return;
        }

        // 챌린지 시작 이벤트 전송
        boolean accepted = stateMachineIntegrator.sendEvent(MfaEvent.INITIATE_CHALLENGE, context, request);

        if (accepted) {
            Map<String, Object> successResponse = createSuccessResponse(context, "CHALLENGE_INITIATED",
                    "챌린지가 시작되었습니다.");
            successResponse.put("factorType", context.getCurrentProcessingFactor());
            successResponse.put("challengeUrl", determineNextStepUrl(context, request));

            responseWriter.writeSuccessResponse(response, successResponse, HttpServletResponse.SC_OK);
        } else {
            Map<String, Object> errorResponse = createErrorResponse(context, "CHALLENGE_INITIATION_FAILED",
                    "챌린지 시작에 실패했습니다.");
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "CHALLENGE_FAILED", "Challenge initiation failed", request.getRequestURI(), errorResponse);
        }
    }

    /**
     * 팩터 검증 처리
     */
    private void handleFactorVerification(HttpServletRequest request, HttpServletResponse response,
                                          FactorContext context, FilterChain filterChain)
            throws ServletException, IOException {
        String sessionId = context.getMfaSessionId();
        log.debug("Handling factor verification for session: {}", sessionId);

        // 검증 가능한 상태인지 확인
        if (context.getCurrentState() != MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION) {
            log.warn("Factor verification requested in invalid state: {} for session: {}",
                    context.getCurrentState(), sessionId);

            Map<String, Object> errorResponse = createErrorResponse(context, "INVALID_STATE_FOR_VERIFICATION",
                    "팩터 검증이 불가능한 상태입니다.");
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "INVALID_STATE", "Invalid state for verification", request.getRequestURI(), errorResponse);
            return;
        }

        // 팩터 검증은 전용 Filter에서 처리하므로 FilterChain으로 위임
        log.debug("Delegating factor verification to specialized filter for session: {}", sessionId);
        filterChain.doFilter(request, response);
    }

    /**
     * 상태 확인 처리
     */
    private void handleStatusCheck(HttpServletRequest request, HttpServletResponse response,
                                   FactorContext context) throws IOException {
        String sessionId = context.getMfaSessionId();
        log.debug("Handling status check for session: {}", sessionId);

        // State Machine에서 최신 상태 조회
        MfaState latestState = stateMachineIntegrator.getCurrentState(sessionId);

        Map<String, Object> statusResponse = new HashMap<>();
        statusResponse.put("mfaSessionId", sessionId);
        statusResponse.put("currentState", latestState.name());
        statusResponse.put("isTerminal", latestState.isTerminal());
        statusResponse.put("availableFactors", context.getRegisteredMfaFactors());
        statusResponse.put("completedFactorsCount", context.getCompletedFactors().size());

        if (context.getCurrentProcessingFactor() != null) {
            statusResponse.put("currentProcessingFactor", context.getCurrentProcessingFactor().name());
            statusResponse.put("currentStepId", context.getCurrentStepId());
        }

        responseWriter.writeSuccessResponse(response, statusResponse, HttpServletResponse.SC_OK);
    }

    /**
     * 세션 갱신 처리
     */
    private void handleSessionRefresh(HttpServletRequest request, HttpServletResponse response,
                                      FactorContext context) throws IOException {
        String sessionId = context.getMfaSessionId();
        log.debug("Handling session refresh for session: {}", sessionId);

        // 마지막 활동 시간 업데이트
        context.updateLastActivityTimestamp();

        // State Machine에 저장
        stateMachineIntegrator.saveFactorContext(context);

        Map<String, Object> refreshResponse = createSuccessResponse(context, "SESSION_REFRESHED",
                "세션이 갱신되었습니다.");
        refreshResponse.put("refreshedAt", System.currentTimeMillis());

        responseWriter.writeSuccessResponse(response, refreshResponse, HttpServletResponse.SC_OK);
    }

    /**
     * MFA 취소 처리
     */
    private void handleCancelMfa(HttpServletRequest request, HttpServletResponse response,
                                 FactorContext context) throws IOException {
        String sessionId = context.getMfaSessionId();
        log.info("Handling MFA cancellation for session: {}", sessionId);

        // 취소 이벤트 전송
        boolean accepted = stateMachineIntegrator.sendEvent(MfaEvent.USER_ABORTED_MFA, context, request);

        if (accepted) {
            Map<String, Object> cancelResponse = createSuccessResponse(context, "MFA_CANCELLED",
                    "MFA가 취소되었습니다.");
            cancelResponse.put("redirectUrl", request.getContextPath() + "/loginForm");

            responseWriter.writeSuccessResponse(response, cancelResponse, HttpServletResponse.SC_OK);

            // 세션 정리
            stateMachineIntegrator.cleanupSession(request);
        } else {
            Map<String, Object> errorResponse = createErrorResponse(context, "CANCELLATION_FAILED",
                    "MFA 취소에 실패했습니다.");
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "CANCELLATION_FAILED", "MFA cancellation failed", request.getRequestURI(), errorResponse);
        }
    }

    /**
     * 지원하지 않는 요청 처리
     */
    private void handleUnsupportedRequest(HttpServletRequest request, HttpServletResponse response,
                                          FactorContext context, MfaRequestType requestType) throws IOException {
        String sessionId = context.getMfaSessionId();
        log.warn("Unsupported request type: {} for session: {}", requestType, sessionId);

        Map<String, Object> errorResponse = createErrorResponse(context, "UNSUPPORTED_REQUEST",
                "지원하지 않는 요청 타입입니다: " + requestType);
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                "UNSUPPORTED_REQUEST", "Unsupported request type", request.getRequestURI(), errorResponse);
    }

    // === 유틸리티 메서드들 ===

    private Map<String, Object> createSuccessResponse(FactorContext context, String status, String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", status);
        response.put("message", message);
        response.put("mfaSessionId", context.getMfaSessionId());
        response.put("currentState", context.getCurrentState().name());
        response.put("storageType", "UNIFIED_STATE_MACHINE");
        return response;
    }

    private Map<String, Object> createErrorResponse(FactorContext context, String error, String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("error", error);
        response.put("message", message);
        response.put("mfaSessionId", context.getMfaSessionId());
        response.put("currentState", context.getCurrentState().name());
        response.put("storageType", "UNIFIED_STATE_MACHINE");
        return response;
    }

    private String determineNextStepUrl(FactorContext context, HttpServletRequest request) {
        if (context.getCurrentProcessingFactor() == null) {
            return request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl();
        }

        return switch (context.getCurrentProcessingFactor()) {
            case OTT -> request.getContextPath() +
                    authContextProperties.getMfa().getOttFactor().getRequestCodeUiUrl();
            case PASSKEY -> request.getContextPath() +
                    authContextProperties.getMfa().getPasskeyFactor().getChallengeUrl();
            default -> request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl();
        };
    }
}