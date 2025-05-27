package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.core.session.MfaSessionRepository;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportResult;
import io.springsecurity.springsecurity6x.security.utils.writer.AuthResponseWriter;
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
    private final MfaSessionRepository sessionRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        log.info("UnifiedAuthenticationSuccessHandler: Processing authentication success for user: {} using {} repository",
                authentication.getName(), sessionRepository.getRepositoryType());

        // 개선: Repository 패턴을 통한 FactorContext 로드 (HttpSession 직접 접근 제거)
        FactorContext factorContext = stateMachineIntegrator.loadFactorContextFromRequest(request);
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

            stateMachineIntegrator.sendEvent(MfaEvent.ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN, factorContext, request);

            handleFinalAuthenticationSuccess(request, response, factorContext.getPrimaryAuthentication(), factorContext);
            return;
        }

        // 2. 1차 인증 성공 직후 처리
        if (factorContext == null || !Objects.equals(factorContext.getUsername(), username)) {
            log.error("Invalid FactorContext state after primary authentication using {} repository",
                    sessionRepository.getRepositoryType());
            handleInvalidContext(response, request, "INVALID_CONTEXT", "인증 컨텍스트가 유효하지 않습니다.", authentication);
            return;
        }

        // 개선: Repository를 통한 세션 검증
        if (!sessionRepository.existsSession(factorContext.getMfaSessionId())) {
            log.warn("MFA session {} not found in {} repository during authentication success",
                    factorContext.getMfaSessionId(), sessionRepository.getRepositoryType());
            handleInvalidContext(response, request, "SESSION_NOT_FOUND",
                    "MFA 세션을 찾을 수 없습니다.", authentication);
            return;
        }

        log.debug("Evaluating MFA requirement for user: {}", username);
        mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(authentication, factorContext);

        stateMachineIntegrator.syncStateWithStateMachine(factorContext, request);

        // MFA 필요 여부에 따른 이벤트 전송 및 응답 처리
        if (!factorContext.isMfaRequiredAsPerPolicy() || factorContext.getCurrentState() == MfaState.MFA_NOT_REQUIRED) {
            log.info("MFA not required for user: {}. Proceeding with final authentication success.", username);

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

            stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, factorContext, request);
            handleConfigError(response, request, factorContext, "MFA 처리 중 예상치 못한 상태입니다.");
        }
    }

    /**
     * MFA 응답 본문 생성 (Repository 정보 추가)
     */
    private Map<String, Object> createMfaResponseBody(String status, String message,
                                                      FactorContext factorContext, String nextStepUrl) {
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("status", status);
        responseBody.put("message", message);
        responseBody.put("mfaSessionId", factorContext.getMfaSessionId());
        responseBody.put("nextStepUrl", nextStepUrl);

        // 개선: Repository 정보 추가
        Map<String, Object> sessionInfo = new HashMap<>();
        sessionInfo.put("currentState", factorContext.getCurrentState().name());
        sessionInfo.put("sessionId", factorContext.getMfaSessionId());
        sessionInfo.put("repositoryType", sessionRepository.getRepositoryType()); // 추가
        sessionInfo.put("distributedSync", sessionRepository.supportsDistributedSync()); // 추가

        responseBody.put("sessionInfo", sessionInfo);
        return responseBody;
    }

    /**
     * 개선: Repository 패턴 통합된 최종 인증 성공 처리
     */
    private void handleFinalAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                  Authentication finalAuthentication,
                                                  @Nullable FactorContext factorContext) throws IOException {
        log.info("All authentication steps completed for user: {}. Issuing final tokens using {} repository.",
                finalAuthentication.getName(), sessionRepository.getRepositoryType());

        String deviceIdFromCtx = factorContext != null ?
                (String) factorContext.getAttribute("deviceId") : null;

        String accessToken = tokenService.createAccessToken(finalAuthentication, deviceIdFromCtx);
        String refreshTokenVal = null;
        if (tokenService.properties().isEnableRefreshToken()) {
            refreshTokenVal = tokenService.createRefreshToken(finalAuthentication, deviceIdFromCtx);
        }

        // 개선: Repository 패턴을 통한 세션 정리 (HttpSession 직접 접근 제거)
        if (factorContext != null && factorContext.getMfaSessionId() != null) {
            stateMachineIntegrator.releaseStateMachine(factorContext.getMfaSessionId());

            // Repository를 통한 세션 제거
            sessionRepository.removeSession(factorContext.getMfaSessionId(), request, response);

            // HttpSession 에서도 MFA 세션 ID 제거 (호환성 유지)
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.removeAttribute("MFA_SESSION_ID");
            }
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

        // 개선: Repository 정보 추가
        responseBody.put("repositoryType", sessionRepository.getRepositoryType());
        responseBody.put("distributedSync", sessionRepository.supportsDistributedSync());

        responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
    }

    /**
     * 개선: Repository 패턴을 통한 무효한 컨텍스트 처리 (HttpSession 직접 접근 제거)
     */
    private void handleInvalidContext(HttpServletResponse response, HttpServletRequest request,
                                      String errorCode, String logMessage,
                                      @Nullable Authentication authentication) throws IOException {
        log.warn("Invalid FactorContext using {} repository: {}. User: {}",
                sessionRepository.getRepositoryType(), logMessage,
                (authentication != null ? authentication.getName() : "Unknown"));

        // 개선: Repository를 통한 세션 정리 (HttpSession 직접 접근 제거)
        String oldSessionId = sessionRepository.getSessionId(request);
        if (oldSessionId != null) {
            try {
                stateMachineIntegrator.releaseStateMachine(oldSessionId);
                sessionRepository.removeSession(oldSessionId, request, response);

                // HttpSession에서도 정리 (호환성 유지)
                HttpSession session = request.getSession(false);
                if (session != null) {
                    session.removeAttribute("MFA_SESSION_ID");
                }
            } catch (Exception e) {
                log.warn("Failed to cleanup invalid session using {} repository: {}",
                        sessionRepository.getRepositoryType(), oldSessionId, e);
            }
        }

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("repositoryType", sessionRepository.getRepositoryType()); // 추가

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, errorCode,
                "MFA 세션 컨텍스트 오류: " + logMessage, request.getRequestURI(), errorResponse);
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