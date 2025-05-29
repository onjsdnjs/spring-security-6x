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

public final class PrimaryAuthenticationSuccessHandler extends AbstractMfaAuthenticationSuccessHandler  {

    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthResponseWriter responseWriter;
    private final AuthContextProperties authContextProperties;
    private final RequestCache requestCache = new HttpSessionRequestCache();
    private final String defaultTargetUrl = "/home";
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSessionRepository sessionRepository;

    public PrimaryAuthenticationSuccessHandler(MfaPolicyProvider mfaPolicyProvider, TokenService tokenService, AuthResponseWriter responseWriter, AuthContextProperties authContextProperties, ApplicationContext applicationContext, MfaStateMachineIntegrator stateMachineIntegrator, MfaSessionRepository sessionRepository) {
        super(tokenService,responseWriter,sessionRepository,stateMachineIntegrator,authContextProperties);
        this.mfaPolicyProvider = mfaPolicyProvider;
        this.responseWriter = responseWriter;
        this.authContextProperties = authContextProperties;
        this.stateMachineIntegrator = stateMachineIntegrator;
        this.sessionRepository = sessionRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        log.info("UnifiedAuthenticationSuccessHandler: Processing authentication success for user: {} using {} repository",
                authentication.getName(), sessionRepository.getRepositoryType());

        // State Machine 에서 FactorContext 로드 (Repository 패턴)
        FactorContext factorContext = stateMachineIntegrator.loadFactorContextFromRequest(request);
        String username = authentication.getName();

        // FactorContext 유효성 검증
        if (factorContext == null || !Objects.equals(factorContext.getUsername(), username)) {
            log.error("Invalid FactorContext state after primary authentication using {} repository",
                    sessionRepository.getRepositoryType());
            handleInvalidContext(response, request, "INVALID_CONTEXT", "인증 컨텍스트가 유효하지 않습니다.", authentication);
            return;
        }

        //Repository를 통한 세션 검증
        if (!sessionRepository.existsSession(factorContext.getMfaSessionId())) {
            log.warn("MFA session {} not found in {} repository during authentication success",
                    factorContext.getMfaSessionId(), sessionRepository.getRepositoryType());
            handleInvalidContext(response, request, "SESSION_NOT_FOUND",
                    "MFA 세션을 찾을 수 없습니다.", authentication);
            return;
        }

        //1차 인증 완료 처리 (RestAuthenticationFilter 에서 이관)
//        processPrimaryAuthenticationCompletion(factorContext, request);

        // State Machine과 동기화
        stateMachineIntegrator.syncStateWithStateMachine(factorContext, request);

        //MFA 정책 평가 (이벤트 전송은 PolicyProvider 에서)
        log.debug("Evaluating MFA requirement for user: {}", username);
        mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(authentication, factorContext);

        //정책 평가 후 State Machine과 재동기화
        stateMachineIntegrator.syncStateWithStateMachine(factorContext, request);

        //현재 상태에 따른 응답 생성 (상태 체크 로직 개선)
        MfaState currentState = factorContext.getCurrentState();

        switch (currentState) {
            case MFA_NOT_REQUIRED, MFA_SUCCESSFUL:
                log.info("MFA not required for user: {}. Proceeding with final authentication success.", username);
                handleFinalAuthenticationSuccess(request, response, authentication, factorContext);
                break;

            case MFA_CONFIGURATION_REQUIRED:
                log.info("MFA configuration required for user: {}", username);
                handleMfaConfigurationRequired(request, response, factorContext);
                break;

            case AWAITING_FACTOR_SELECTION:
                log.info("MFA required for user: {}. State: AWAITING_FACTOR_SELECTION", username);
                handleFactorSelectionRequired(request, response, factorContext);
                break;

            case AWAITING_FACTOR_CHALLENGE_INITIATION:
                log.info("MFA required for user: {}. Proceeding directly to challenge", username);
                handleDirectChallenge(request, response, factorContext);
                break;

            default:
                log.error("Unexpected FactorContext state ({}) for user {} after policy evaluation",
                        currentState, username);
                stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, factorContext, request);
                handleConfigError(response, request, factorContext, "MFA 처리 중 예상치 못한 상태입니다.");
        }
    }

    // 상태별 응답 처리 메서드들
    private void handleFactorSelectionRequired(HttpServletRequest request, HttpServletResponse response,
                                               FactorContext factorContext) throws IOException {
        Map<String, Object> responseBody = createMfaResponseBody(
                "MFA_REQUIRED",
                "추가 인증이 필요합니다. 인증 수단을 선택해주세요.",
                factorContext,
                request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl()
        );
        responseBody.put("availableFactors", factorContext.getRegisteredMfaFactors());
        responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
    }

    private void handleDirectChallenge(HttpServletRequest request, HttpServletResponse response,
                                       FactorContext factorContext) throws IOException {
        AuthType nextFactor = factorContext.getCurrentProcessingFactor();
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
    }

    private void handleMfaConfigurationRequired(HttpServletRequest request, HttpServletResponse response,
                                                FactorContext factorContext) throws IOException {
        String mfaConfigUrl = request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl();
        Map<String, Object> responseBody = createMfaResponseBody(
                "MFA_CONFIG_REQUIRED",
                "MFA 설정이 필요합니다.",
                factorContext,
                mfaConfigUrl
        );

        responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
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