package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ExtendedContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
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
 * 최종 리팩토링된 UnifiedAuthenticationSuccessHandler
 * 통합된 ContextPersistence 사용
 */
@Slf4j
@RequiredArgsConstructor
public class UnifiedAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final ContextPersistence contextPersistence; // 통합된 인터페이스 사용
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
        log.info("UnifiedAuthenticationSuccessHandler: Processing authentication success for user: {} (persistence: {})",
                authentication.getName(),
                contextPersistence instanceof ExtendedContextPersistence ?
                        ((ExtendedContextPersistence) contextPersistence).getPersistenceType() : "BASIC");

        // ContextPersistence에서 로드 (저장소 타입에 관계없이)
        FactorContext factorContext = contextPersistence.contextLoad(request);
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

        // 저장소 타입 정보 추가
        if (contextPersistence instanceof ExtendedContextPersistence) {
            ExtendedContextPersistence extended = (ExtendedContextPersistence) contextPersistence;
            stateMachineInfo.put("persistenceType", extended.getPersistenceType().name());
        }

        responseBody.put("stateMachine", stateMachineInfo);
        return responseBody;
    }

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

        // State Machine 정리
        if (factorContext != null && factorContext.getMfaSessionId() != null) {
            stateMachineIntegrator.releaseStateMachine(factorContext.getMfaSessionId());
        }

        // ContextPersistence 정리 (저장소 타입에 관계없이)
        contextPersistence.deleteContext(request);

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
        if (contextPersistence instanceof ExtendedContextPersistence) {
            ExtendedContextPersistence extended = (ExtendedContextPersistence) contextPersistence;
            responseBody.put("persistenceType", extended.getPersistenceType().name());
        }

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