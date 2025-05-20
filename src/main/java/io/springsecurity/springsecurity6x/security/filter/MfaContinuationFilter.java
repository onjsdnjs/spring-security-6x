package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

@Slf4j
public class MfaContinuationFilter extends OncePerRequestFilter {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final OrRequestMatcher requestMatcher;

    public MfaContinuationFilter(ContextPersistence contextPersistence,
                                 MfaPolicyProvider mfaPolicyProvider,
                                 AuthContextProperties authContextProperties,
                                 AuthResponseWriter responseWriter,
                                 ApplicationContext applicationContext) { // EmailOneTimeTokenService 제거
        this.contextPersistence = Objects.requireNonNull(contextPersistence);
        this.mfaPolicyProvider = Objects.requireNonNull(mfaPolicyProvider);
        this.authContextProperties = Objects.requireNonNull(authContextProperties);
        this.responseWriter = Objects.requireNonNull(responseWriter);
        this.applicationContext = Objects.requireNonNull(applicationContext);

        String mfaInitiatePath = authContextProperties.getMfa().getInitiateUrl();
        Assert.hasText(mfaInitiatePath, "spring.auth.mfa.initiate-url must be configured");

        this.requestMatcher = new OrRequestMatcher(
                new AntPathRequestMatcher(mfaInitiatePath, HttpMethod.GET.name()),
                new AntPathRequestMatcher("/mfa/select-factor", HttpMethod.GET.name()),
                // MFA OTT 코드 "생성 요청" UI 페이지
                new AntPathRequestMatcher("/mfa/ott/request-code-ui", HttpMethod.GET.name()),
                // MFA OTT 코드 "입력" UI 페이지 (MfaContinuationFilter가 안내, 실제 제출은 JS가 POST)
                new AntPathRequestMatcher("/mfa/challenge/ott", HttpMethod.GET.name()),
                // MFA Passkey 챌린지 UI 페이지
                new AntPathRequestMatcher("/mfa/challenge/passkey", HttpMethod.GET.name())
        );
        log.info("MfaContinuationFilter initialized. Listening on: {}, /mfa/select-factor, /mfa/ott/request-code-ui, /mfa/challenge/** (GET)", mfaInitiatePath);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!this.requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("MfaContinuationFilter processing GET request: {}", request.getRequestURI());
        FactorContext ctx = contextPersistence.contextLoad(request);

        if (ctx == null || !StringUtils.hasText(ctx.getMfaSessionId()) || !StringUtils.hasText(ctx.getFlowTypeName())) {
            handleInvalidContext(request, response, "mfa_session_missing_or_corrupted_MfaContFilter", "MFA 세션이 없거나 손상되었습니다.");
            return;
        }
        if (ctx.getCurrentState() == null || ctx.getCurrentState().isTerminal()) {
            handleTerminalContext(request, response, ctx);
            return;
        }

        AuthenticationFlowConfig currentMfaFlowConfig = findFlowConfigByName(ctx.getFlowTypeName());
        if (currentMfaFlowConfig == null && "mfa".equalsIgnoreCase(ctx.getFlowTypeName())) {
            handleConfigError(response, request, "MFA_FLOW_CONFIG_MISSING_CTX_MfaContFilter", "MFA 플로우 설정을 찾을 수 없습니다 (컨텍스트).");
            return;
        }

        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        String mfaInitiateFullUrl = contextPath + authContextProperties.getMfa().getInitiateUrl();
        String selectFactorFullUiUrl = contextPath + "/mfa/select-factor";
        String mfaOttRequestCodeUiFullUrl = contextPath + "/mfa/ott/request-code-ui";
        String challengeUiBaseFullUrl = contextPath + "/mfa/challenge/";

        try {
            if (requestUri.equals(mfaInitiateFullUrl)) {
                handleMfaInitiationRequest(request, response, ctx, selectFactorFullUiUrl, challengeUiBaseFullUrl);
            } else if (requestUri.equals(selectFactorFullUiUrl)) {
                handleSelectFactorPageRequest(request, response, filterChain, ctx);
            } else if (requestUri.equals(mfaOttRequestCodeUiFullUrl)) {
                handleMfaOttRequestCodeUiPageRequest(request, response, filterChain, ctx);
            } else if (requestUri.startsWith(challengeUiBaseFullUrl)) {
                handleFactorChallengeInputUiPageRequest(request, response, filterChain, ctx, requestUri, challengeUiBaseFullUrl, currentMfaFlowConfig);
            } else {
                filterChain.doFilter(request, response);
            }
        } catch (Exception e) {
            handleGenericError(request, response, ctx, e);
        }
    }

    private void handleMfaInitiationRequest(HttpServletRequest request, HttpServletResponse response, FactorContext ctx, String selectFactorUrl, String challengeBaseUrl) throws IOException {
        if (ctx.isMfaRequiredAsPerPolicy() &&
                (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION ||
                        ctx.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)) {
            log.info("MfaContinuationFilter: Guiding MFA initiation for user: {}, Session: {}, State: {}", ctx.getUsername(), ctx.getMfaSessionId(), ctx.getCurrentState());
            if (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION && ctx.getCurrentProcessingFactor() != null) {
                String factorNameLower = ctx.getCurrentProcessingFactor().name().toLowerCase();
                if (ctx.getCurrentProcessingFactor() == AuthType.OTT) {
                    response.sendRedirect(request.getContextPath() + "/mfa/ott/request-code-ui"); // OTT는 코드 생성 요청 UI로
                } else {
                    response.sendRedirect(challengeBaseUrl + factorNameLower); // 다른 Factor는 챌린지 UI로
                }
            } else { // AWAITING_FACTOR_SELECTION 또는 Factor 미정 시
                response.sendRedirect(selectFactorUrl);
            }
        } else {
            log.warn("MfaContinuationFilter: Invalid state ({}) or MFA not required for MFA initiation. Session: {}", ctx.getCurrentState(), ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + "/loginForm?error=invalid_mfa_initiation_context_state");
        }
    }

    private void handleSelectFactorPageRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, FactorContext ctx) throws IOException, ServletException {
        if (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION) {
            log.info("MfaContinuationFilter: Rendering /mfa/select-factor page. Session: {}", ctx.getMfaSessionId());
            filterChain.doFilter(request, response); // LoginController가 UI 렌더링
        } else {
            log.warn("MfaContinuationFilter: Invalid state ({}) for /mfa/select-factor. Session: {}", ctx.getCurrentState(), ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + "/loginForm?error=invalid_state_for_mfa_page");
        }
    }

    private void handleMfaOttRequestCodeUiPageRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, FactorContext ctx) throws IOException, ServletException {
        // 이 페이지는 MfaApiController.selectFactor에서 OTT 선택 시, 또는 1차 인증 후 바로 OTT로 안내될 때 도달.
        // FactorContext.currentProcessingFactor가 OTT이고, 상태가 AWAITING_FACTOR_CHALLENGE_INITIATION 이어야 함.
        if (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION &&
                ctx.getCurrentProcessingFactor() == AuthType.OTT &&
                StringUtils.hasText(ctx.getCurrentStepId())) {
            log.info("MfaContinuationFilter: Rendering MFA OTT code request UI. Session: {}, StepId: {}", ctx.getMfaSessionId(), ctx.getCurrentStepId());
            // 이 페이지의 폼 action은 Spring Security GenerateOneTimeTokenFilter가 처리하는 경로
            // (예: /mfa/ott/generate - POST)를 가리켜야 함.
            filterChain.doFilter(request, response); // LoginController가 UI 렌더링
        } else {
            log.warn("MfaContinuationFilter: Invalid context for /mfa/ott/request-code-ui. State: {}, Factor: {}, StepId: {}. Session: {}",
                    ctx.getCurrentState(), ctx.getCurrentProcessingFactor(), ctx.getCurrentStepId(), ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + "/mfa/select-factor?error=invalid_ott_request_ui_context");
        }
    }

    // 특정 Factor의 "챌린지 입력/검증" UI 페이지 요청 처리 (예: GET /mfa/challenge/ott -> OTT 코드 "입력" UI)
    private void handleFactorChallengeInputUiPageRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, FactorContext ctx, String requestUri, String challengeUiBaseFullUrl, @Nullable AuthenticationFlowConfig flowConfig) throws IOException, ServletException {
        String factorTypeSegment = requestUri.substring(challengeUiBaseFullUrl.length());
        AuthType requestedFactor;
        try {
            requestedFactor = AuthType.valueOf(factorTypeSegment.toUpperCase());
        } catch (IllegalArgumentException e) {
            log.warn("Invalid factor type in challenge UI URL: {}. Session: {}", factorTypeSegment, ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + "/mfa/select-factor?error=invalid_challenge_page_url");
            return;
        }

        // 상태 및 Factor 일치, stepId 유효성 검사
        // 이 페이지로 오기 전, AWAITING_FACTOR_CHALLENGE_INITIATION 상태에서 MfaPolicyProvider 또는 MfaApiController가
        // currentProcessingFactor, currentStepId, currentFactorOptions를 설정했어야 함.
        if (ctx.getCurrentState() != MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION ||
                ctx.getCurrentProcessingFactor() != requestedFactor ||
                !StringUtils.hasText(ctx.getCurrentStepId())) {
            log.warn("Challenge UI for factor {} requested with invalid context. State: {}, CtxFactor: {}, CtxStepId: {}. Session: {}",
                    requestedFactor, ctx.getCurrentState(), ctx.getCurrentProcessingFactor(), ctx.getCurrentStepId(), ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + "/mfa/select-factor?error=invalid_challenge_input_page_context");
            return;
        }

        // currentFactorOptions가 이전에 설정되었는지 확인. 없다면 flowConfig에서 가져와 설정.
        if (ctx.getCurrentFactorOptions() == null && flowConfig != null) {
            setFactorOptionsInContext(ctx, requestedFactor, flowConfig);
        }

        // OTT의 경우, 코드 생성은 이전 단계(/mfa/ott/request-code-ui -> POST /mfa/ott/generate)에서 이미 완료.
        // 이 필터는 단순히 코드 "입력" UI로 안내.
        if (requestedFactor == AuthType.OTT) {
            log.info("MFA OTT Code Input UI page request for user {} (session {}). Code should have been sent.",
                    ctx.getUsername(), ctx.getMfaSessionId());
        }
        // Passkey의 경우도, 이 필터는 Passkey 인증 UI 페이지로 안내.
        // 클라이언트 JS가 /api/mfa/assertion/options를 호출하여 챌린지 옵션을 받고 navigator.credentials.get() 실행.

        // 다음 상태: 이 Factor에 대한 사용자의 입력/응답을 기다림
        ctx.changeState(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
        contextPersistence.saveContext(ctx, request);
        log.info("MfaContinuationFilter: Proceeding to render challenge input UI for factor {} (stepId: {}, session {}). New state: {}",
                requestedFactor, ctx.getCurrentStepId(), ctx.getMfaSessionId(), ctx.getCurrentState());
        filterChain.doFilter(request, response); // LoginController가 실제 UI 페이지 렌더링
    }


    private void handleInvalidContext(HttpServletRequest request, HttpServletResponse response, String errorCode, String errorMessage) throws IOException {
        log.warn("MfaContinuationFilter: Invalid FactorContext. ErrorCode: {}, Message: {}, Request: {}", errorCode, errorMessage, request.getRequestURI());
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, errorCode, errorMessage, request.getRequestURI());
    }

    private void handleTerminalContext(HttpServletRequest request, HttpServletResponse response, FactorContext ctx) throws IOException {
        log.info("MfaContinuationFilter: FactorContext (ID: {}) is terminal (State: {}). Clearing context for user {}.",
                ctx.getMfaSessionId(), ctx.getCurrentState(), ctx.getUsername());
        contextPersistence.deleteContext(request);
        response.sendRedirect(request.getContextPath() + "/loginForm?error=mfa_session_already_ended");
    }
    private void handleConfigError(HttpServletResponse response, HttpServletRequest request, String errorCode, String errorMessage) throws IOException {
        log.error("MfaContinuationFilter: Configuration error. ErrorCode: {}, Message: {}, Request: {}", errorCode, errorMessage, request.getRequestURI());
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, errorCode, errorMessage, request.getRequestURI());
    }
    private void handleGenericError(HttpServletRequest request, HttpServletResponse response, FactorContext ctx, Exception e) throws IOException {
        log.error("Error during MFA continuation for session {}: {}", (ctx != null ? ctx.getMfaSessionId() : "N/A"), e.getMessage(), e);
        if (!response.isCommitted()) {
            String mfaFailurePage = request.getContextPath() + authContextProperties.getMfa().getFailureUrl();
            response.sendRedirect(mfaFailurePage + "?error=" + "mfa_filter_exception");
        }
    }

    private void setFactorOptionsInContext(FactorContext ctx, AuthType factorType, @Nullable AuthenticationFlowConfig flowConfig) {
        // ... (이전 답변의 로직 유지)
    }

    @Nullable
    private AuthenticationFlowConfig findFlowConfigByName(String flowTypeName) {
        // ... (이전 답변의 로직 유지)
        if (!StringUtils.hasText(flowTypeName)) return null;
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            if (platformConfig != null && platformConfig.getFlows() != null) {
                return platformConfig.getFlows().stream()
                        .filter(flow -> flowTypeName.equalsIgnoreCase(flow.getTypeName()))
                        .findFirst()
                        .orElse(null);
            }
        } catch (Exception e) {log.warn("Cannot find FlowConfig for {}: {}", flowTypeName, e.getMessage());}
        return null;
    }
}