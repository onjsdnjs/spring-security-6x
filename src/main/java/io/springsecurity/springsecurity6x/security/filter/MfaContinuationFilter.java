package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.service.ott.EmailOneTimeTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
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
    @Nullable
    private final EmailOneTimeTokenService emailOttService;
    private final RequestMatcher requestMatcher;
    private final ApplicationContext applicationContext;

    public MfaContinuationFilter(ContextPersistence contextPersistence,
                                 MfaPolicyProvider mfaPolicyProvider,
                                 AuthContextProperties authContextProperties,
                                 AuthResponseWriter responseWriter,
                                 @Nullable EmailOneTimeTokenService emailOttService,
                                 ApplicationContext applicationContext) {
        this.contextPersistence = Objects.requireNonNull(contextPersistence);
        this.mfaPolicyProvider = Objects.requireNonNull(mfaPolicyProvider);
        this.authContextProperties = Objects.requireNonNull(authContextProperties);
        this.responseWriter = Objects.requireNonNull(responseWriter);
        this.emailOttService = emailOttService;
        this.applicationContext = Objects.requireNonNull(applicationContext);

        String mfaInitiatePath = authContextProperties.getMfa().getInitiateUrl();
        Assert.hasText(mfaInitiatePath, "spring.auth.mfa.initiate-url must be configured");

        this.requestMatcher = new OrRequestMatcher(
                new AntPathRequestMatcher(mfaInitiatePath, HttpMethod.GET.name()),
                new AntPathRequestMatcher("/mfa/select-factor", HttpMethod.GET.name()),
                new AntPathRequestMatcher("/mfa/challenge/**", HttpMethod.GET.name())
        );
        log.info("MfaContinuationFilter initialized. Listening on: {}, /mfa/select-factor, /mfa/challenge/** (GET)", mfaInitiatePath);
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

        if (ctx == null || !StringUtils.hasText(ctx.getMfaSessionId())) {
            log.warn("MfaContinuationFilter: No valid FactorContext for request: {}. Redirecting to login.", request.getRequestURI());
            response.sendRedirect(request.getContextPath() + "/loginForm?error=mfa_session_missing_or_invalid");
            return;
        }

        if (ctx.getCurrentState() == null || ctx.getCurrentState().isTerminal()) {
            log.info("MfaContinuationFilter: FactorContext (ID: {}) is in terminal state ({}) or state is null. Clearing context. User: {}",
                    ctx.getMfaSessionId(), ctx.getCurrentState(), ctx.getUsername());
            contextPersistence.deleteContext(request);
            response.sendRedirect(request.getContextPath() + "/loginForm?error=mfa_session_ended");
            return;
        }
        // 현재 MFA 플로우 설정을 FactorContext에 저장된 flowTypeName을 기반으로 로드
        AuthenticationFlowConfig currentMfaFlowConfig = findFlowConfigByName(ctx.getFlowTypeName());
        if (currentMfaFlowConfig == null && "mfa".equalsIgnoreCase(ctx.getFlowTypeName())) { // MFA 플로우인데 설정을 못 찾으면 오류
            log.error("MfaContinuationFilter: MFA flow '{}' configuration not found for FactorContext (ID: {}). Cannot proceed.",
                    ctx.getFlowTypeName(), ctx.getMfaSessionId());
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA_FLOW_CONFIG_ERROR", "MFA 플로우 설정을 찾을 수 없습니다.", request.getRequestURI());
            return;
        }


        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        String mfaInitiateUrlConfigured = authContextProperties.getMfa().getInitiateUrl();
        String mfaInitiateFullUrl = contextPath + mfaInitiateUrlConfigured;
        String selectFactorFullUiUrl = contextPath + "/mfa/select-factor";
        String challengeUiBaseFullUrl = contextPath + "/mfa/challenge/";

        try {
            if (requestUri.equals(mfaInitiateFullUrl)) {
                // 1차 인증 성공 핸들러가 FactorContext의 상태를 PRIMARY_AUTHENTICATION_COMPLETED로 설정하고,
                // MfaPolicyProvider를 통해 mfaRequiredAsPerPolicy, currentProcessingFactor 등을 설정한 후 호출됨.
                if (ctx.getCurrentState() == MfaState.PRIMARY_AUTHENTICATION_COMPLETED && ctx.isMfaRequiredAsPerPolicy()) {
                    handleMfaInitiation(request, response, ctx, currentMfaFlowConfig);
                } else if (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION) { // 이미 Factor 선택 단계로 넘어간 경우
                    log.debug("MFA already in AWAITING_FACTOR_SELECTION state. Redirecting to select-factor page. Session: {}", ctx.getMfaSessionId());
                    response.sendRedirect(selectFactorFullUiUrl);
                }
                else if (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION && ctx.getCurrentProcessingFactor() != null) { // 이미 특정 Factor 챌린지 대기
                    log.debug("MFA already in AWAITING_FACTOR_CHALLENGE_INITIATION for {}. Redirecting to its challenge page. Session: {}", ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());
                    response.sendRedirect(challengeUiBaseFullUrl + ctx.getCurrentProcessingFactor().name().toLowerCase());
                }
                else {
                    log.warn("MfaContinuationFilter: Invalid state ({}) or MFA not required for MFA initiation request. Session: {}", ctx.getCurrentState(), ctx.getMfaSessionId());
                    response.sendRedirect(contextPath + "/loginForm?error=invalid_mfa_initiation_context");
                }
                return;
            }
            else if (requestUri.equals(selectFactorFullUiUrl)) {
                if (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION) {
                    // MfaApiController에서 Factor 선택 후, 이 페이지로 GET 리다이렉션 된 것이 아니므로,
                    // currentProcessingFactor, currentStepId, currentFactorOptions는 아직 설정되지 않았거나 null 이어야 함.
                    ctx.setCurrentProcessingFactor(null);
                    ctx.setCurrentFactorOptions(null);
                    ctx.setCurrentStepId(null);
                    contextPersistence.saveContext(ctx, request); // 상태 및 정보 초기화 후 저장
                    log.info("MfaContinuationFilter: Navigating to /mfa/select-factor page. Session: {}", ctx.getMfaSessionId());
                    filterChain.doFilter(request, response); // LoginController가 UI 렌더링
                } else {
                    log.warn("MfaContinuationFilter: Invalid state ({}) for accessing /mfa/select-factor. Session: {}", ctx.getCurrentState(), ctx.getMfaSessionId());
                    response.sendRedirect(contextPath + "/loginForm?error=invalid_state_for_factor_selection");
                }
                return;
            }
            else if (requestUri.startsWith(challengeUiBaseFullUrl)) {
                // MfaApiController에서 Factor 선택 후, /mfa/challenge/{factorType} 으로 GET 리다이렉션되어 호출됨.
                // 이 시점에는 FactorContext에 currentProcessingFactor, currentFactorOptions, currentStepId가 설정되어 있어야 함.
                handleFactorChallengeUiRequest(request, response, ctx, requestUri, challengeUiBaseFullUrl, filterChain, currentMfaFlowConfig);
                return;
            }

            filterChain.doFilter(request, response);

        } catch (Exception e) {
            // ... (기존 예외 처리)
            log.error("Error during MFA continuation processing for session {}: {}", ctx.getMfaSessionId(), e.getMessage(), e);
            if (!response.isCommitted()) {
                String mfaFailurePage = contextPath + authContextProperties.getMfa().getFailureUrl();
                response.sendRedirect(mfaFailurePage + "?error=" + "mfa_flow_exception_occurred");
            }
        }
    }

    private void handleMfaInitiation(HttpServletRequest request, HttpServletResponse response, FactorContext ctx, @Nullable AuthenticationFlowConfig flowConfig) throws IOException {
        // 이 메소드는 1차 인증 성공 핸들러에서 MfaPolicyProvider를 통해 FactorContext의
        // mfaRequiredAsPerPolicy, currentProcessingFactor, (옵션 및 stepId는 핸들러가 설정)
        // 그리고 다음 MfaState (AWAITING_FACTOR_SELECTION 또는 AWAITING_FACTOR_CHALLENGE_INITIATION)가
        // 이미 설정된 후에 호출된다고 가정.
        // 여기서는 FactorContext의 현재 상태와 정보를 기반으로 적절한 UI로 리다이렉트.
        log.info("MfaContinuationFilter: Handling MFA initiation for user: {}, Session: {}, CurrentState: {}",
                ctx.getUsername(), ctx.getMfaSessionId(), ctx.getCurrentState());

        if (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION && ctx.getCurrentProcessingFactor() != null) {
            // 특정 Factor로 바로 진행
            String factorName = ctx.getCurrentProcessingFactor().name().toLowerCase();
            // 이 시점에 ctx.currentStepId와 ctx.currentFactorOptions는 1차 인증 성공 핸들러에서 설정되어 있어야 함.
            if (ctx.getCurrentStepId() == null || ctx.getCurrentFactorOptions() == null) {
                log.warn("MfaContinuationFilter: currentStepId or currentFactorOptions is null for factor {} in MFA initiation. Session: {}", factorName, ctx.getMfaSessionId());
                // 안전하게 Factor 선택 페이지로 보내거나 오류 처리
            }
            log.info("Redirecting to challenge UI for factor: {}. Session: {}", factorName, ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + "/mfa/challenge/" + factorName);
        } else if (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION) {
            // Factor 선택 페이지로
            log.info("Redirecting to factor selection page. Session: {}", ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + "/mfa/select-factor");
        } else {
            log.warn("Unexpected state {} during MFA initiation for session {}. Redirecting to select factor as fallback.", ctx.getCurrentState(), ctx.getMfaSessionId());
            ctx.changeState(MfaState.AWAITING_FACTOR_SELECTION);
            contextPersistence.saveContext(ctx, request);
            response.sendRedirect(request.getContextPath() + "/mfa/select-factor");
        }
    }

    private void handleFactorChallengeUiRequest(HttpServletRequest request, HttpServletResponse response, FactorContext ctx, String requestUri, String challengeUiBaseFullUrl, FilterChain filterChain, @Nullable AuthenticationFlowConfig flowConfig) throws IOException, ServletException {
        String factorTypeSegment = requestUri.substring(challengeUiBaseFullUrl.length());
        AuthType requestedFactor;
        try {
            requestedFactor = AuthType.valueOf(factorTypeSegment.toUpperCase());
        } catch (IllegalArgumentException e) {
            log.warn("Invalid factor type in challenge UI URL: {}. Session: {}", factorTypeSegment, ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + "/mfa/select-factor?error=invalid_factor_url");
            return;
        }

        log.debug("MfaContinuationFilter: Handling GET for MFA challenge UI. Requested: {}, ContextFactor: {}, ContextState: {}, ContextStepId: {}, Session: {}",
                requestedFactor, ctx.getCurrentProcessingFactor(), ctx.getCurrentState(), ctx.getCurrentStepId(), ctx.getMfaSessionId());

        // MfaApiController.selectFactor 후 또는 1차 인증 성공 핸들러에서 이 페이지로 리다이렉션.
        // 이때 FactorContext.currentProcessingFactor, currentStepId, currentFactorOptions가 설정되어 있어야 함.
        // 상태는 AWAITING_FACTOR_CHALLENGE_INITIATION 이어야 함.
        if (ctx.getCurrentState() != MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION ||
                ctx.getCurrentProcessingFactor() != requestedFactor ||
                !StringUtils.hasText(ctx.getCurrentStepId()) ) { // currentStepId 유효성 검사 추가
            log.warn("Challenge UI for factor {} requested with invalid context. State: {}, CtxFactor: {}, CtxStepId: {}. Session: {}",
                    requestedFactor, ctx.getCurrentState(), ctx.getCurrentProcessingFactor(), ctx.getCurrentStepId(), ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + "/mfa/select-factor?error=invalid_challenge_context");
            return;
        }

        // currentFactorOptions가 아직 설정되지 않았다면 (이론적으로는 이전 단계에서 설정되어야 함) 여기서 다시 시도
        if (ctx.getCurrentFactorOptions() == null && flowConfig != null) {
            setFactorOptionsInContext(ctx, requestedFactor, flowConfig);
        }


        if (requestedFactor == AuthType.OTT) {
            if (emailOttService != null) {
                try {
                    emailOttService.generate(new GenerateOneTimeTokenRequest(ctx.getUsername()));
                    log.info("MFA OTT code generation requested for user {} (session {}) before rendering OTT challenge UI.", ctx.getUsername(), ctx.getMfaSessionId());
                } catch (Exception e) {
                    // ... (기존 OTT 발송 실패 처리) ...
                    log.error("MfaContinuationFilter: Failed to request OTT code generation for user {} (session {}): {}", ctx.getUsername(), ctx.getMfaSessionId(), e.getMessage(), e);
                    response.sendRedirect(request.getContextPath() + "/mfa/select-factor?error=ott_send_failure");
                    return;
                }
            } else {
                // ... (기존 emailOttService null 처리) ...
                log.error("EmailOneTimeTokenService is null. Cannot request OTT code generation for MFA. Session: {}", ctx.getMfaSessionId());
                responseWriter.writeErrorResponse(response, HttpStatus.INTERNAL_SERVER_ERROR.value(), "OTT_SERVICE_UNCONFIGURED", "OTT 서비스가 설정되지 않았습니다.", request.getRequestURI());
                return;
            }
        }
        // Passkey의 경우, MfaApiController.getMfaPasskeyAssertionOptions가 클라이언트 JS에서 호출되어 옵션을 가져가므로,
        // 이 필터는 해당 UI 페이지로의 접근 허용 및 상태 변경만 수행.

        ctx.changeState(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
        contextPersistence.saveContext(ctx, request);
        log.info("MfaContinuationFilter: Proceeding to render challenge UI for factor {} (stepId: {}, session {}). New state: {}",
                requestedFactor, ctx.getCurrentStepId(), ctx.getMfaSessionId(), ctx.getCurrentState());
        filterChain.doFilter(request, response); // LoginController가 실제 UI 페이지 렌더링
    }

    private void setFactorOptionsInContext(FactorContext ctx, AuthType factorType, @Nullable AuthenticationFlowConfig flowConfig) {
        // ... (이전 답변의 setFactorOptionsInContext 로직과 동일하게 사용) ...
        if (factorType == null) {
            ctx.setCurrentFactorOptions(null);
            return;
        }
        if (flowConfig != null && flowConfig.getRegisteredFactorOptions() != null) {
            AuthenticationProcessingOptions factorOptions = flowConfig.getRegisteredFactorOptions().get(factorType);
            ctx.setCurrentFactorOptions(factorOptions);
            if (factorOptions == null) {
                log.warn("MfaContinuationFilter: No specific options found for factor {} in flow config for user {}. FactorContext.currentFactorOptions will be null.", factorType, ctx.getUsername());
            }
        } else {
            log.warn("MfaContinuationFilter: AuthenticationFlowConfig or registeredFactorOptions not available. Cannot set currentFactorOptions for factor {} and user {}.", factorType, ctx.getUsername());
            ctx.setCurrentFactorOptions(null);
        }
    }

    @Nullable
    private AuthenticationFlowConfig findFlowConfigByName(String flowTypeName) {
        // ... (이전 답변의 findFlowConfigByName 로직과 동일하게 사용) ...
        if (!StringUtils.hasText(flowTypeName)) return null;
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            if (platformConfig != null && platformConfig.getFlows() != null) {
                return platformConfig.getFlows().stream()
                        .filter(flow -> flowTypeName.equalsIgnoreCase(flow.getTypeName()))
                        .findFirst()
                        .orElseGet(() -> {
                            log.warn("No AuthenticationFlowConfig found with typeName: {}", flowTypeName);
                            return null;
                        });
            }
        } catch (Exception e) {
            log.warn("MfaContinuationFilter: Error retrieving PlatformConfig or flow configuration for type {}: {}", flowTypeName, e.getMessage());
        }
        return null;
    }
}