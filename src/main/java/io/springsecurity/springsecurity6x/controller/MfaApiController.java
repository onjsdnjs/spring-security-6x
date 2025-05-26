package io.springsecurity.springsecurity6x.controller;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * 완전 일원화된 MfaApiController
 * - ContextPersistence 완전 제거
 * - MfaStateMachineIntegrator를 통한 고수준 비즈니스 로직 처리
 * - State Machine 기반 상태 관리
 */
@Slf4j
@RestController
@RequestMapping("/api/mfa")
@RequiredArgsConstructor
public class MfaApiController {

    // ContextPersistence 완전 제거, MfaStateMachineService 제거
    private final MfaStateMachineIntegrator stateMachineIntegrator; // 고수준 통합자만 사용
    private final AuthContextProperties authContextProperties;

    /**
     * 완전 일원화: MFA 팩터 선택 API
     */
    @PostMapping("/select-factor")
    public ResponseEntity<Map<String, Object>> selectFactor(@RequestBody Map<String, String> request,
                                                            HttpServletRequest httpRequest) {
        String factorType = request.get("factor");

        // 입력 검증
        if (!StringUtils.hasText(factorType)) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "MISSING_FACTOR",
                    "Factor type is required", null);
        }

        // 완전 일원화: State Machine 통합자에서 FactorContext 로드
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(httpRequest);

        if (!isValidMfaContext(ctx)) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_MFA_SESSION",
                    "Invalid or expired MFA session", ctx);
        }

        // 상태 검증 - 팩터 선택 가능한 상태인지 확인
        if (ctx.getCurrentState() != MfaState.AWAITING_FACTOR_SELECTION) {
            log.warn("Factor selection attempted in invalid state: {} for session: {}",
                    ctx.getCurrentState(), ctx.getMfaSessionId());
            return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_STATE",
                    "Cannot select factor in current state: " + ctx.getCurrentState(), ctx);
        }

        // 요청된 팩터가 사용 가능한지 확인
        AuthType requestedFactorType;
        try {
            requestedFactorType = AuthType.valueOf(factorType.toUpperCase());
        } catch (IllegalArgumentException e) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_FACTOR_TYPE",
                    "Invalid factor type: " + factorType, ctx);
        }

        if (!ctx.getRegisteredMfaFactors().contains(requestedFactorType)) {
            log.warn("User {} attempted to select unavailable factor: {}",
                    ctx.getUsername(), requestedFactorType);
            return createErrorResponse(HttpStatus.BAD_REQUEST, "FACTOR_NOT_AVAILABLE",
                    "Factor type not available for user: " + requestedFactorType, ctx);
        }

        try {
            // 선택된 팩터를 컨텍스트에 임시 저장 (State Machine에서 사용)
            ctx.setAttribute("selectedFactorType", requestedFactorType.name());

            // 완전 일원화: State Machine 통합자를 통해 이벤트 전송
            boolean accepted = stateMachineIntegrator.sendEvent(
                    MfaEvent.FACTOR_SELECTED, ctx, httpRequest
            );

            if (accepted) {
                // State Machine과 동기화 (최신 상태 반영)
                stateMachineIntegrator.syncStateWithStateMachine(ctx, httpRequest);

                String nextStepUrl = determineNextStepUrl(ctx, httpRequest);

                Map<String, Object> successResponse = createSuccessResponse(
                        "FACTOR_SELECTED", "Factor selected successfully", ctx);
                successResponse.put("selectedFactor", requestedFactorType.name());
                successResponse.put("nextStepUrl", nextStepUrl);
                successResponse.put("currentState", ctx.getCurrentState().name());

                log.info("Factor {} selected successfully for user {} (session: {})",
                        requestedFactorType, ctx.getUsername(), ctx.getMfaSessionId());

                return ResponseEntity.ok(successResponse);
            } else {
                log.error("State Machine rejected FACTOR_SELECTED event for session: {} in state: {}",
                        ctx.getMfaSessionId(), ctx.getCurrentState());
                return createErrorResponse(HttpStatus.BAD_REQUEST, "EVENT_REJECTED",
                        "Invalid state for factor selection", ctx);
            }

        } catch (Exception e) {
            log.error("Error selecting factor {} for session: {}", factorType, ctx.getMfaSessionId(), e);

            // State Machine에 에러 이벤트 전송
            try {
                stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, ctx, httpRequest);
            } catch (Exception eventError) {
                log.error("Failed to send SYSTEM_ERROR event", eventError);
            }

            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "FACTOR_SELECTION_FAILED",
                    "Failed to select factor", ctx);
        }
    }

    /**
     * 완전 일원화: MFA 취소 API
     */
    @PostMapping("/cancel")
    public ResponseEntity<Map<String, Object>> cancelMfa(HttpServletRequest httpRequest) {
        // 완전 일원화: State Machine 통합자에서 FactorContext 로드
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(httpRequest);

        if (!isValidMfaContext(ctx)) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_MFA_SESSION",
                    "Invalid or expired MFA session", null);
        }

        // 터미널 상태에서는 취소 불가
        if (ctx.getCurrentState().isTerminal()) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "ALREADY_TERMINAL",
                    "MFA process is already completed or terminated", ctx);
        }

        try {
            // 완전 일원화: State Machine 통합자를 통해 취소 이벤트 전송
            boolean accepted = stateMachineIntegrator.sendEvent(
                    MfaEvent.USER_ABORTED_MFA, ctx, httpRequest
            );

            if (accepted) {
                // State Machine과 동기화
                stateMachineIntegrator.syncStateWithStateMachine(ctx, httpRequest);

                Map<String, Object> successResponse = createSuccessResponse(
                        "MFA_CANCELLED", "MFA cancelled successfully", ctx);
                successResponse.put("redirectUrl", getContextPath(httpRequest) + "/loginForm");

                log.info("MFA cancelled by user {} (session: {})",
                        ctx.getUsername(), ctx.getMfaSessionId());

                // 세션 정리
                stateMachineIntegrator.cleanupSession(httpRequest);

                return ResponseEntity.ok(successResponse);
            } else {
                log.warn("State Machine rejected USER_ABORTED_MFA event for session: {} in state: {}",
                        ctx.getMfaSessionId(), ctx.getCurrentState());
                return createErrorResponse(HttpStatus.BAD_REQUEST, "CANCELLATION_REJECTED",
                        "Cannot cancel MFA in current state: " + ctx.getCurrentState(), ctx);
            }

        } catch (Exception e) {
            log.error("Error cancelling MFA for session: {}", ctx.getMfaSessionId(), e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "CANCELLATION_FAILED",
                    "Failed to cancel MFA", ctx);
        }
    }

    /**
     * 완전 일원화: MFA 상태 조회 API (새로 추가)
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getMfaStatus(HttpServletRequest httpRequest) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(httpRequest);

        if (!isValidMfaContext(ctx)) {
            return createErrorResponse(HttpStatus.NOT_FOUND, "NO_MFA_SESSION",
                    "No active MFA session found", null);
        }

        try {
            // State Machine과 동기화
            stateMachineIntegrator.syncStateWithStateMachine(ctx, httpRequest);

            Map<String, Object> statusResponse = new HashMap<>();
            statusResponse.put("status", "ACTIVE");
            statusResponse.put("mfaSessionId", ctx.getMfaSessionId());
            statusResponse.put("username", ctx.getUsername());
            statusResponse.put("currentState", ctx.getCurrentState().name());
            statusResponse.put("flowType", ctx.getFlowTypeName());
            statusResponse.put("isTerminal", ctx.getCurrentState().isTerminal());
            statusResponse.put("registeredFactors", ctx.getRegisteredMfaFactors());
            statusResponse.put("completedFactorsCount", ctx.getCompletedFactors().size());
            statusResponse.put("storageType", "UNIFIED_STATE_MACHINE");

            if (ctx.getCurrentProcessingFactor() != null) {
                statusResponse.put("currentProcessingFactor", ctx.getCurrentProcessingFactor().name());
                statusResponse.put("currentStepId", ctx.getCurrentStepId());
            }

            return ResponseEntity.ok(statusResponse);

        } catch (Exception e) {
            log.error("Error retrieving MFA status for session: {}", ctx.getMfaSessionId(), e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "STATUS_RETRIEVAL_FAILED",
                    "Failed to retrieve MFA status", ctx);
        }
    }

    /**
     * 완전 일원화: OTT 코드 재전송 API (새로 추가)
     */
    @PostMapping("/request-ott-code")
    public ResponseEntity<Map<String, Object>> requestOttCode(HttpServletRequest httpRequest) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(httpRequest);

        if (!isValidMfaContext(ctx)) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_MFA_SESSION",
                    "Invalid or expired MFA session", null);
        }

        // OTT 팩터 처리 중인지 확인
        if (ctx.getCurrentProcessingFactor() != AuthType.OTT) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_FACTOR",
                    "OTT code request is only available during OTT factor processing", ctx);
        }

        try {
            // OTT 코드 재전송 이벤트 전송
            boolean accepted = stateMachineIntegrator.sendEvent(
                    MfaEvent.INITIATE_CHALLENGE, ctx, httpRequest
            );

            if (accepted) {
                Map<String, Object> successResponse = createSuccessResponse(
                        "OTT_CODE_REQUESTED", "OTT code has been resent", ctx);

                return ResponseEntity.ok(successResponse);
            } else {
                return createErrorResponse(HttpStatus.BAD_REQUEST, "REQUEST_REJECTED",
                        "Cannot request OTT code in current state", ctx);
            }

        } catch (Exception e) {
            log.error("Error requesting OTT code for session: {}", ctx.getMfaSessionId(), e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "OTT_REQUEST_FAILED",
                    "Failed to request OTT code", ctx);
        }
    }

    // === 유틸리티 메서드들 ===

    /**
     * 완전 일원화: MFA 컨텍스트 유효성 검증
     */
    private boolean isValidMfaContext(FactorContext ctx) {
        return ctx != null &&
                StringUtils.hasText(ctx.getUsername()) &&
                StringUtils.hasText(ctx.getMfaSessionId()) &&
                !ctx.getCurrentState().isTerminal();
    }

    /**
     * 완전 일원화: 다음 단계 URL 결정 (설정 기반)
     */
    private String determineNextStepUrl(FactorContext ctx, HttpServletRequest request) {
        String contextPath = getContextPath(request);
        AuthType currentFactor = ctx.getCurrentProcessingFactor();

        if (currentFactor == null) {
            return contextPath + authContextProperties.getMfa().getSelectFactorUrl();
        }

        return switch (currentFactor) {
            case OTT -> contextPath + authContextProperties.getMfa().getOttFactor().getRequestCodeUiUrl();
            case PASSKEY -> contextPath + authContextProperties.getMfa().getPasskeyFactor().getChallengeUrl();
            default -> {
                log.warn("Unknown factor type for next step determination: {}", currentFactor);
                yield contextPath + authContextProperties.getMfa().getSelectFactorUrl();
            }
        };
    }

    /**
     * 성공 응답 생성
     */
    private Map<String, Object> createSuccessResponse(String status, String message, FactorContext ctx) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", status);
        response.put("message", message);
        response.put("timestamp", System.currentTimeMillis());
        response.put("storageType", "UNIFIED_STATE_MACHINE");

        if (ctx != null) {
            response.put("mfaSessionId", ctx.getMfaSessionId());
            response.put("currentState", ctx.getCurrentState().name());
        }

        return response;
    }

    /**
     * 에러 응답 생성
     */
    private ResponseEntity<Map<String, Object>> createErrorResponse(HttpStatus status, String errorCode,
                                                                    String message, FactorContext ctx) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", errorCode);
        errorResponse.put("message", message);
        errorResponse.put("timestamp", System.currentTimeMillis());
        errorResponse.put("storageType", "UNIFIED_STATE_MACHINE");

        if (ctx != null) {
            errorResponse.put("mfaSessionId", ctx.getMfaSessionId());
            errorResponse.put("currentState", ctx.getCurrentState().name());
        }

        return ResponseEntity.status(status).body(errorResponse);
    }

    /**
     * Context Path 조회
     */
    private String getContextPath(HttpServletRequest request) {
        return request.getContextPath();
    }
}