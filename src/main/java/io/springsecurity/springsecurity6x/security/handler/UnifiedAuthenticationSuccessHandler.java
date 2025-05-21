package io.springsecurity.springsecurity6x.security.handler;


import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportResult;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.ResponseCookie;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
public class UnifiedAuthenticationSuccessHandler implements AuthenticationSuccessHandler, OneTimeTokenGenerationSuccessHandler { // 인터페이스 추가

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final TokenService tokenService;
    private final AuthResponseWriter responseWriter;
    private final AuthContextProperties authContextProperties;
    private final ApplicationContext applicationContext;
    private final RequestCache requestCache = new HttpSessionRequestCache();
    private final String defaultTargetUrl = "/home";

    /**
     * 일반적인 인증 성공 시 (1차 인증 성공 또는 MFA 전체 플로우 완료 후) 호출됩니다.
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        log.info("UnifiedAuthenticationSuccessHandler.onAuthenticationSuccess: Authentication event for user: {}. Request URI: {}",
                authentication.getName(), request.getRequestURI());

        FactorContext factorContext = contextPersistence.contextLoad(request);
        String username = authentication.getName();

        // 1. MFA 플로우가 이미 완료된 상태로 이 핸들러가 호출된 경우 (MfaFactorProcessingSuccessHandler 로부터의 위임)
        if (factorContext != null &&
                Objects.equals(factorContext.getUsername(), username) &&
                (factorContext.getCurrentState() == MfaState.MFA_FULLY_COMPLETED)) {
            log.info("MFA flow already completed for user: {}. Proceeding with final token issuance.", username);
            handleFinalAuthenticationSuccess(request, response, factorContext.getPrimaryAuthentication(), factorContext);
            return;
        }

        // 2. 1차 인증 성공 직후 (예: RestAuthenticationFilter 에서 호출)
        // RestAuthenticationFilter 에서 FactorContext를 MfaState.PRIMARY_AUTHENTICATION_COMPLETED 상태로,
        // flowTypeName을 "primary" (또는 null)로 생성하여 세션에 저장했을 것을 가정합니다.
        if (factorContext == null || !Objects.equals(factorContext.getUsername(), username) ||
                (factorContext.getCurrentState() != MfaState.PRIMARY_AUTHENTICATION_COMPLETED &&
                        factorContext.getCurrentState() != MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)) { // AWAITING_MFA_INITIATION은 이전 상태일 수 있음
            // 유효한 FactorContext가 없거나, 1차 인증 완료 상태가 아니면 새로 생성 또는 초기화
            if (factorContext != null) {
                log.warn("Invalid or unexpected FactorContext (ID: {}, User: {}, State: {}, Flow: {}) found for user {}. Clearing and creating a new one.",
                        factorContext.getMfaSessionId(), factorContext.getUsername(), factorContext.getCurrentState(), factorContext.getFlowTypeName(), username);
                contextPersistence.deleteContext(request);
            }
            log.debug("Creating new FactorContext after primary authentication for user: {}", username);
            String mfaSessionId = UUID.randomUUID().toString();
            factorContext = new FactorContext(
                    mfaSessionId,
                    authentication, // 현재 성공한 1차 인증 객체
                    MfaState.PRIMARY_AUTHENTICATION_COMPLETED,
                    AuthType.PRIMARY.name().toLowerCase() // 초기 flowType은 'primary'
            );
            String deviceId = getEffectiveDeviceId(request);
            factorContext.setAttribute("deviceId", deviceId);
            // contextPersistence.saveContext(factorContext, request); // MfaPolicyProvider 호출 후 저장
        }

        // MfaPolicyProvider를 호출하여 MFA 필요 여부 및 초기 단계 설정
        // 이 호출은 factorContext의 mfaRequiredAsPerPolicy, flowTypeName (MFA 필요시 "mfa"로 변경),
        // currentProcessingFactor, currentStepId, currentState 등을 설정합니다.
        log.debug("Calling MfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep for user: {}", username);
        mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(authentication, factorContext);
        contextPersistence.saveContext(factorContext, request); // 정책 평가 및 컨텍스트 업데이트 후 저장

        // FactorContext의 상태에 따라 분기 처리
        if (!factorContext.isMfaRequiredAsPerPolicy() || factorContext.getCurrentState() == MfaState.MFA_NOT_REQUIRED) {
            log.info("MFA not required for user: {}. Proceeding with final authentication success.", username);
            handleFinalAuthenticationSuccess(request, response, authentication, factorContext);
        } else if (factorContext.getCurrentState() == MfaState.MFA_CONFIGURATION_REQUIRED) {
            log.info("MFA configuration required for user: {}. Client should be guided to MFA setup.", username);
            String mfaConfigUrl = request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl(); // 임시로 팩터 선택 페이지
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN, "MFA_CONFIG_REQUIRED",
                    "MFA 설정이 필요합니다. 인증 수단을 등록해주세요.", mfaConfigUrl);

        } else if (factorContext.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION) {

            log.info("MFA required for user: {}. Responding with MFA_REQUIRED_SELECT_FACTOR.", username);
            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("mfaSessionId", factorContext.getMfaSessionId());
            String mfaConfigUrl = request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl(); // 임
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN, "MFA_REQUIRED_SELECT_FACTOR",
                    "추가 인증이 필요합니다. 인증 수단을 선택해주세요.", mfaConfigUrl, responseBody);

        } else if (factorContext.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION &&
                factorContext.getCurrentProcessingFactor() != null &&
                StringUtils.hasText(factorContext.getCurrentStepId())) {
            AuthType nextFactor = factorContext.getCurrentProcessingFactor();
            log.info("MFA required for user: {}. Proceeding directly to {} challenge initiation.", username, nextFactor);

            String nextUiPageUrl;
            if (nextFactor == AuthType.OTT) {
                // 이 URL은 사용자가 OTT 코드 생성을 요청하는 폼이 있는 페이지여야 함.
                nextUiPageUrl = request.getContextPath() + authContextProperties.getMfa().getOttFactor().getRequestCodeUiUrl();
            } else if (nextFactor == AuthType.PASSKEY) {
                // MfaSettings에 passkeyFactor.challengeUrl이 정의되어 있어야 함.
                nextUiPageUrl = request.getContextPath() + authContextProperties.getMfa().getPasskeyFactor().getChallengeUrl();
            } else {
                log.error("Unsupported MFA factor type {} determined for user {}. Redirecting to select factor.", nextFactor, username);
                nextUiPageUrl = request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl(); // 안전 장치
            }

            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("nextFactorType", nextFactor.name());
            responseBody.put("status", "MFA_REQUIRED");
            responseBody.put("nextStepUrl", nextUiPageUrl);
            responseBody.put("nextStepId", factorContext.getCurrentStepId());
            responseBody.put("mfaSessionId", factorContext.getMfaSessionId());

            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);

        } else {
            log.error("UnifiedAuthenticationSuccessHandler: Unexpected FactorContext state ({}) for user {} after policy evaluation. MFA Session ID: {}. This may indicate an issue in MfaPolicyProvider or FactorContext state transitions.",
                    factorContext.getCurrentState(), username, factorContext.getMfaSessionId());
            handleConfigError(response, request, factorContext, "MFA 처리 중 예상치 못한 상태입니다.");
        }
    }

    /**
     * OTT 코드 생성 성공 시 (GenerateOneTimeTokenFilter에 의해) 호출됩니다.
     * @param token 생성된 OneTimeToken (내부 토큰)
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken token) throws IOException, ServletException {
        log.info("UnifiedAuthenticationSuccessHandler.handle (OneTimeTokenGenerationSuccessHandler): OTT code generated for user: {}", token.getUsername());

        FactorContext factorContext = contextPersistence.contextLoad(request);
        String usernameFromToken = token.getUsername();

        if (factorContext == null || !Objects.equals(factorContext.getUsername(), usernameFromToken) ||
                !AuthType.MFA.name().equalsIgnoreCase(factorContext.getFlowTypeName()) ||
                factorContext.getCurrentProcessingFactor() != AuthType.OTT) {
            log.warn("OTT Generation Success: Invalid or missing FactorContext for user {}. " +
                    "Expected MFA flow with OTT processing. Context: {}", usernameFromToken, factorContext);
            // 적절한 오류 페이지로 리다이렉션 또는 에러 응답
            response.sendRedirect(request.getContextPath() + "/loginForm?error=mfa_session_error_on_ott_generation");
            return;
        }

        // 코드 생성이 성공했으므로, 사용자를 코드 입력 페이지로 안내.
        // FactorContext 상태를 '챌린지 제시됨, 검증 대기'로 변경.
        // MfaContinuationFilter가 /mfa/challenge/ott (GET) 요청을 받을 때 이 상태로 변경할 수도 있음.
        // 여기서는 코드 생성이 "성공"했음을 명시하고, 다음 UI로 이동할 준비가 되었음을 나타내는 상태로 변경.
        factorContext.changeState(MfaState.FACTOR_CHALLENGE_SENT_AWAITING_UI); // 또는 FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION
        contextPersistence.saveContext(factorContext, request);
        log.info("MFA FactorContext (ID: {}) state updated to {} for user {} after OTT code generation. Redirecting to OTT challenge page.",
                factorContext.getMfaSessionId(), factorContext.getCurrentState(), factorContext.getUsername());

        String challengeUiUrl = authContextProperties.getMfa().getOttFactor().getChallengeUrl(); // 예: /mfa/challenge/ott
        if (!StringUtils.hasText(challengeUiUrl)) {
            challengeUiUrl = "/mfa/challenge/ott"; // 안전한 기본값
            log.warn("MFA OTT challengeUrl not configured in properties, using default: {}", challengeUiUrl);
        }
        String redirectUrl = request.getContextPath() + challengeUiUrl;

        log.debug("Redirecting to MFA OTT challenge page: {}", redirectUrl);
        response.sendRedirect(redirectUrl);
    }


    /**
     * 모든 인증(1차 또는 최종 MFA) 성공 시 토큰 발급 및 응답 처리
     * @param finalAuthentication 최종적으로 인증된 Authentication 객체 (일반적으로 1차 인증 객체)
     * @param factorContext MFA 플로우를 거친 경우의 컨텍스트, 단일 인증 시 null일 수 있음.
     */
    private void handleFinalAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                  Authentication finalAuthentication, @Nullable FactorContext factorContext) throws IOException {
        if (factorContext != null) {
            log.info("Final authentication success for user: {}. MFA Session ID: {}. Cleaning up FactorContext.",
                    finalAuthentication.getName(), factorContext.getMfaSessionId());
            contextPersistence.deleteContext(request); // 성공 후 MFA 컨텍스트 정리
        } else {
            log.info("Final authentication success for user: {} (No FactorContext involved or already cleaned).", finalAuthentication.getName());
        }

        log.info("MFA not required or all factors completed for user: {}. Issuing final tokens.", finalAuthentication.getName());
        String deviceIdFromCtx = (String) factorContext.getAttribute("deviceId");

        String accessToken = tokenService.createAccessToken(finalAuthentication, deviceIdFromCtx);
        String refreshTokenVal = null;
        if (tokenService.properties().isEnableRefreshToken()) {
            refreshTokenVal = tokenService.createRefreshToken(finalAuthentication, deviceIdFromCtx);
        }

        contextPersistence.deleteContext(request); // MFA 컨텍스트 정리 (최종 성공이므로)

        TokenTransportResult transportResult = tokenService.prepareTokensForTransport(accessToken, refreshTokenVal);

        if (transportResult.getCookiesToSet() != null) {
            for (ResponseCookie cookie : transportResult.getCookiesToSet()) {
                response.addHeader("Set-Cookie", cookie.toString());
            }
        }
        String determineTargetUrl = determineTargetUrl(request, response, finalAuthentication);

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN, "SUCCESS",
                "인증에 성공했습니다", determineTargetUrl);
    }

    private String getEffectiveDeviceId(HttpServletRequest request) {
        String deviceId = request.getHeader("X-Device-Id");
        if (StringUtils.hasText(deviceId)) {
            return deviceId;
        }
        HttpSession session = request.getSession(false);
        if (session != null) {
            deviceId = (String) session.getAttribute("transientDeviceId");
            if (StringUtils.hasText(deviceId)) {
                return deviceId;
            }
        }
        deviceId = UUID.randomUUID().toString();
        session = request.getSession(true); // 세션이 없다면 생성
        session.setAttribute("transientDeviceId", deviceId);
        log.debug("Generated new transient deviceId in UnifiedAuthenticationSuccessHandler: {}", deviceId);
        return deviceId;
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        SavedRequest savedRequest = this.requestCache.getRequest(request, response);
        if (savedRequest != null) {
            this.requestCache.removeRequest(request, response); // 사용 후 제거
            log.debug("Redirecting to saved request URL: {}", savedRequest.getRedirectUrl());
            return savedRequest.getRedirectUrl();
        }
        String targetUrl = request.getContextPath() + defaultTargetUrl;
        log.debug("Redirecting to default target URL: {}", targetUrl);
        return targetUrl;
    }

    @Nullable
    private AuthenticationFlowConfig findFlowConfigByName(String flowTypeName) {
        if (!StringUtils.hasText(flowTypeName)) return null;
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            if (platformConfig != null && platformConfig.getFlows() != null) {
                return platformConfig.getFlows().stream()
                        .filter(flow -> flowTypeName.equalsIgnoreCase(flow.getTypeName()))
                        .findFirst()
                        .orElse(null);
            }
        } catch (Exception e) {
            log.warn("UnifiedAuthenticationSuccessHandler: Error retrieving PlatformConfig or flow configuration for type {}: {}", flowTypeName, e.getMessage());
        }
        return null;
    }

    private void handleConfigError(HttpServletResponse response, HttpServletRequest request, @Nullable FactorContext ctx, String message) throws IOException {
        String flowTypeName = (ctx != null && StringUtils.hasText(ctx.getFlowTypeName())) ? ctx.getFlowTypeName() : "Unknown Flow";
        String username = (ctx != null && StringUtils.hasText(ctx.getUsername())) ? ctx.getUsername() : "Unknown User";
        log.error("Configuration error for flow '{}', user '{}': {}", flowTypeName, username, message);

        String errorCode = "MFA_FLOW_CONFIG_ERROR";
        if (ctx != null) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    errorCode, message, request.getRequestURI(), Map.of("mfaSessionId", ctx.getMfaSessionId()));
            contextPersistence.deleteContext(request);
        } else {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    errorCode, message, request.getRequestURI());
        }
    }
}
