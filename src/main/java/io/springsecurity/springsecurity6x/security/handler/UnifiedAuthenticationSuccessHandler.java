package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.core.service.MfaStateMachineService;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportResult;
import io.springsecurity.springsecurity6x.security.utils.AuthResponseWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.ResponseCookie;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 완전 일원화된 UnifiedAuthenticationSuccessHandler
 * - ContextPersistence 완전 제거
 * - MfaStateMachineService만 사용
 * - State Machine에서 직접 컨텍스트 로드 및 관리
 */
@Slf4j
@RequiredArgsConstructor
public class UnifiedAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final MfaPolicyProvider mfaPolicyProvider;
    private final TokenService tokenService;
    private final AuthResponseWriter responseWriter;
    private final AuthContextProperties authContextProperties;
    private final ApplicationContext applicationContext;
    private final RequestCache requestCache = new HttpSessionRequestCache();
    private final String defaultTargetUrl = "/home";
    private final MfaStateMachineIntegrator stateMachineIntegrator;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        log.info("UnifiedAuthenticationSuccessHandler: Processing authentication success for user: {} via unified State Machine",
                authentication.getName());

        // 완전 일원화: State Machine에서만 FactorContext 로드
        FactorContext factorContext = loadFactorContextFromStateMachine(request);
        String username = authentication.getName();

        // State Machine과 동기화
        if (factorContext != null) {
            stateMachineIntegrator.syncStateWithStateMachine(factorContext, request);
        }

        // 1. MFA 플로우가 이미 완료된 상태
        if (factorContext != null &&
                Objects.equals(factorContext.getUsername(), username) &&
                (factorContext.getCurrentState() == MfaState.ALL_FACTORS_COMPLETED ||
                        factorContext.getCurrentState() == MfaState.MFA_SUCCESSFUL)) {

            log.info("MFA flow already completed for user: {}. Proceeding with final token issuance.", username);

            // ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN 이벤트 전송
            stateMachineIntegrator.sendEvent(MfaEvent.ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN, factorContext, request);

            handleFinalAuthenticationSuccess(request, response, factorContext.getPrimaryAuthentication(), factorContext);
            return;
        }

        // 2. 1차 인증 성공 직후 처리
        if (factorContext == null || !Objects.equals(factorContext.getUsername(), username)) {
            log.error("Invalid FactorContext state after primary authentication");
            handleInvalidContext(response, request, "INVALID_CONTEXT",
                    "인증 컨텍스트가 유효하지 않습니다.", authentication);
            return;
        }

        // MfaPolicyProvider를 호출하여 MFA 필요 여부 평가
        log.debug("Evaluating MFA requirement for user: {}", username);
        mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(authentication, factorContext);

        // State Machine과 동기화
        stateMachineIntegrator.syncStateWithStateMachine(factorContext, request);

        // MFA 필요 여부에 따른 이벤트 전송 및 응답 처리
        if (!factorContext.isMfaRequiredAsPerPolicy() || factorContext.getCurrentState() == MfaState.MFA_NOT_REQUIRED) {
            log.info("MFA not required for user: {}. Proceeding with final authentication success.", username);

            // MFA_NOT_REQUIRED 이벤트 전송
            stateMachineIntegrator.sendEvent(MfaEvent.MFA_NOT_REQUIRED, factorContext, request);

            handleFinalAuthenticationSuccess(request, response, authentication, factorContext);

        } else if (factorContext.getCurrentState() == MfaState.MFA_CONFIGURATION_REQUIRED) {
            log.info("MFA configuration required for user: {}", username);

            String mfaConfigUrl = request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl();
            Map<String, Object> responseBody = createMfaResponseBody(
                    "MFA_CONFIG_REQUIRED",
                    "MFA 설정이 필요합니다.",
                    factorContext,
                    mfaConfigUrl
            );

            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN,
                    "MFA_CONFIG_REQUIRED", "MFA 설정이 필요합니다.", mfaConfigUrl, responseBody);

        } else if (factorContext.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION) {
            log.info("MFA required for user: {}. State: AWAITING_FACTOR_SELECTION", username);

            // MFA_REQUIRED_SELECT_FACTOR 이벤트 전송
            stateMachineIntegrator.sendEvent(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, factorContext, request);

            Map<String, Object> responseBody = createMfaResponseBody(
                    "MFA_REQUIRED",
                    "추가 인증이 필요합니다. 인증 수단을 선택해주세요.",
                    factorContext,
                    request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl()
            );
            responseBody.put("availableFactors", factorContext.getRegisteredMfaFactors());

            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);

        } else if (factorContext.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION &&
                factorContext.getCurrentProcessingFactor() != null) {

            AuthType nextFactor = factorContext.getCurrentProcessingFactor();
            log.info("MFA required for user: {}. Proceeding directly to {} challenge", username, nextFactor);

            // MFA_REQUIRED_INITIATE_CHALLENGE 이벤트 전송
            stateMachineIntegrator.sendEvent(MfaEvent.MFA_REQUIRED_INITIATE_CHALLENGE, factorContext, request);

            String nextUiPageUrl = determineChalllengeUrl(factorContext, request);

            Map<String, Object> responseBody = createMfaResponseBody(
                    "MFA_REQUIRED",
                    "추가 인증이 필요합니다.",
                    factorContext,
                    nextUiPageUrl
            );
            responseBody.put("nextFactorType", nextFactor.name());
            responseBody.put("nextStepId", factorContext.getCurrentStepId());

            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);

        } else {
            log.error("Unexpected FactorContext state ({}) for user {} after policy evaluation",
                    factorContext.getCurrentState(), username);

            // SYSTEM_ERROR 이벤트 전송
            stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, factorContext, request);

            handleConfigError(response, request, factorContext, "MFA 처리 중 예상치 못한 상태입니다.");
        }
    }

    /**
     * 완전 일원화: State Machine에서만 FactorContext 로드
     */
    private FactorContext loadFactorContextFromStateMachine(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            log.trace("No HttpSession found for request. Cannot load FactorContext.");
            return null;
        }

        String mfaSessionId = (String) session.getAttribute("MFA_SESSION_ID");
        if (mfaSessionId == null) {
            log.trace("No MFA session ID found in session. Cannot load FactorContext.");
            return null;
        }

        try {
            // State Machine에서 직접 로드 (일원화)
            return stateMachineIntegrator.loadFactorContext(mfaSessionId);
        } catch (Exception e) {
            log.error("Failed to load FactorContext from State Machine for session: {}", mfaSessionId, e);
            return null;
        }
    }

    /**
     * MFA 응답 본문 생성 (공통 로직)
     */
    private Map<String, Object> createMfaResponseBody(String status, String message,
                                                      FactorContext factorContext, String nextStepUrl) {
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("status", status);
        responseBody.put("message", message);
        responseBody.put("mfaSessionId", factorContext.getMfaSessionId());
        responseBody.put("nextStepUrl", nextStepUrl);

        // State Machine 정보 추가
        Map<String, Object> stateMachineInfo = new HashMap<>();
        stateMachineInfo.put("currentState", factorContext.getCurrentState().name());
        stateMachineInfo.put("sessionId", factorContext.getMfaSessionId());
        stateMachineInfo.put("storageType", "UNIFIED_STATE_MACHINE");

        responseBody.put("stateMachine", stateMachineInfo);
        return responseBody;
    }

    /**
     * 완전 일원화: 최종 인증 성공 처리
     * - State Machine 정리
     * - 세션 정리
     */
    private void handleFinalAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                  Authentication finalAuthentication,
                                                  @Nullable FactorContext factorContext) throws IOException {
        log.info("All authentication steps completed for user: {}. Issuing final tokens.",
                finalAuthentication.getName());

        String deviceIdFromCtx = factorContext != null ?
                (String) factorContext.getAttribute("deviceId") : null;

        String accessToken = tokenService.createAccessToken(finalAuthentication, deviceIdFromCtx);
        String refreshTokenVal = null;
        if (tokenService.properties().isEnableRefreshToken()) {
            refreshTokenVal = tokenService.createRefreshToken(finalAuthentication, deviceIdFromCtx);
        }

        // 완전 일원화: State Machine 정리
        if (factorContext != null && factorContext.getMfaSessionId() != null) {
            stateMachineIntegrator.releaseStateMachine(factorContext.getMfaSessionId());
        }

        // 세션에서 MFA 세션 ID 정리
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute("MFA_SESSION_ID");
        }

        TokenTransportResult transportResult = tokenService.prepareTokensForTransport(accessToken, refreshTokenVal);

        if (transportResult.getCookiesToSet() != null) {
            for (ResponseCookie cookie : transportResult.getCookiesToSet()) {
                response.addHeader("Set-Cookie", cookie.toString());
            }
        }

        String redirectUrl = determineTargetUrl(request, response, finalAuthentication);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("status", "SUCCESS");
        responseBody.put("message", "인증이 완료되었습니다.");
        responseBody.put("redirectUrl", redirectUrl);
        responseBody.put("accessToken", accessToken);
        if (refreshTokenVal != null) {
            responseBody.put("refreshToken", refreshTokenVal);
        }

        // 완료 통계 정보 추가
        responseBody.put("storageType", "UNIFIED_STATE_MACHINE");

        responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
    }

    private String determineChalllengeUrl(FactorContext ctx, HttpServletRequest request) {
        if (ctx.getCurrentProcessingFactor() == null) {
            return request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl();
        }

        return switch (ctx.getCurrentProcessingFactor()) {
            case OTT -> request.getContextPath() +
                    authContextProperties.getMfa().getOttFactor().getRequestCodeUiUrl();
            case PASSKEY -> request.getContextPath() +
                    authContextProperties.getMfa().getPasskeyFactor().getChallengeUrl();
            default -> request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl();
        };
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {
        SavedRequest savedRequest = this.requestCache.getRequest(request, response);
        if (savedRequest != null) {
            this.requestCache.removeRequest(request, response);
            log.debug("Redirecting to saved request URL: {}", savedRequest.getRedirectUrl());
            return savedRequest.getRedirectUrl();
        }
        String targetUrl = request.getContextPath() + defaultTargetUrl;
        log.debug("Redirecting to default target URL: {}", targetUrl);
        return targetUrl;
    }

    private void handleInvalidContext(HttpServletResponse response, HttpServletRequest request,
                                      String errorCode, String logMessage,
                                      @Nullable Authentication authentication) throws IOException {
        log.warn("Invalid FactorContext: {}. User: {}", logMessage,
                (authentication != null ? authentication.getName() : "Unknown"));

        // 세션에서 잘못된 MFA 세션 ID 정리
        HttpSession session = request.getSession(false);
        if (session != null) {
            String oldSessionId = (String) session.getAttribute("MFA_SESSION_ID");
            if (oldSessionId != null) {
                try {
                    stateMachineIntegrator.releaseStateMachine(oldSessionId);
                } catch (Exception e) {
                    log.warn("Failed to release invalid State Machine session: {}", oldSessionId, e);
                }
                session.removeAttribute("MFA_SESSION_ID");
            }
        }

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, errorCode,
                "MFA 세션 컨텍스트 오류: " + logMessage, request.getRequestURI());
    }

    private void handleConfigError(HttpServletResponse response, HttpServletRequest request,
                                   @Nullable FactorContext ctx, String message) throws IOException {
        String flowTypeName = (ctx != null && StringUtils.hasText(ctx.getFlowTypeName())) ?
                ctx.getFlowTypeName() : "Unknown";
        String username = (ctx != null && StringUtils.hasText(ctx.getUsername())) ?
                ctx.getUsername() : "Unknown";
        log.error("Configuration error for flow '{}', user '{}': {}", flowTypeName, username, message);

        String errorCode = "MFA_FLOW_CONFIG_ERROR";
        if (ctx != null) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    errorCode, message, request.getRequestURI(),
                    Map.of("mfaSessionId", ctx.getMfaSessionId()));
        } else {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    errorCode, message, request.getRequestURI());
        }
    }
}