package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig; // 추가
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig; // 추가
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions; // 추가
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
import org.springframework.context.ApplicationContext; // 추가
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
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
    private final ApplicationContext applicationContext; // ApplicationContext 주입

    public MfaContinuationFilter(ContextPersistence contextPersistence,
                                 MfaPolicyProvider mfaPolicyProvider,
                                 AuthContextProperties authContextProperties,
                                 AuthResponseWriter responseWriter,
                                 @Nullable EmailOneTimeTokenService emailOttService,
                                 ApplicationContext applicationContext) { // 생성자에 ApplicationContext 추가
        this.contextPersistence = Objects.requireNonNull(contextPersistence);
        this.mfaPolicyProvider = Objects.requireNonNull(mfaPolicyProvider);
        this.authContextProperties = Objects.requireNonNull(authContextProperties);
        this.responseWriter = Objects.requireNonNull(responseWriter);
        this.emailOttService = emailOttService;
        this.applicationContext = Objects.requireNonNull(applicationContext); // 주입

        String mfaInitiatePath = authContextProperties.getMfa().getInitiateUrl();
        Assert.hasText(mfaInitiatePath, "spring.auth.mfa.initiate-url must be configured");

        this.requestMatcher = new OrRequestMatcher(
                new AntPathRequestMatcher(mfaInitiatePath, HttpMethod.GET.name()),
                new AntPathRequestMatcher("/mfa/select-factor", HttpMethod.GET.name()),
                new AntPathRequestMatcher("/mfa/challenge/**", HttpMethod.GET.name())
        );
        log.info("MfaContinuationFilter initialized. Listening for MFA UI flow GET requests on: {}, /mfa/select-factor, /mfa/challenge/**", mfaInitiatePath);
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

        if (ctx == null || ctx.getMfaSessionId() == null) {
            log.warn("MfaContinuationFilter: No valid FactorContext for request: {}. Redirecting to login.", request.getRequestURI());
            response.sendRedirect(request.getContextPath() + "/loginForm?error=mfa_session_missing");
            return;
        }

        if (ctx.getCurrentState() == null || ctx.getCurrentState().isTerminal()) {
            log.debug("MfaContinuationFilter: FactorContext for session {} is in terminal state {} or state is null. Clearing context and redirecting to login.",
                    ctx.getMfaSessionId(), ctx.getCurrentState());
            contextPersistence.deleteContext(request);
            response.sendRedirect(request.getContextPath() + "/loginForm?error=mfa_session_terminated");
            return;
        }

        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        String mfaInitiateUrlConfigured = authContextProperties.getMfa().getInitiateUrl();
        String mfaInitiateFullUrl = contextPath + mfaInitiateUrlConfigured;
        String selectFactorFullUiUrl = contextPath + "/mfa/select-factor";
        String challengeUiBaseFullUrl = contextPath + "/mfa/challenge/";

        try {
            AuthenticationFlowConfig currentMfaFlowConfig = findCurrentMfaFlowConfig(); // 현재 MFA Flow 설정 로드

            if (requestUri.equals(mfaInitiateFullUrl)) {
                if (ctx.getCurrentState() == MfaState.PRIMARY_AUTHENTICATION_COMPLETED && ctx.isMfaRequiredAsPerPolicy()) {
                    handleMfaInitiation(request, response, ctx, currentMfaFlowConfig);
                } else {
                    log.warn("MfaContinuationFilter: Invalid state ({}) or MFA not required for MFA initiation request. Session: {}", ctx.getCurrentState(), ctx.getMfaSessionId());
                    response.sendRedirect(contextPath + "/loginForm?error=invalid_mfa_initiation_state");
                }
                return;
            }
            else if (requestUri.equals(selectFactorFullUiUrl)) {
                if (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION ||
                        (ctx.getCurrentState() == MfaState.PRIMARY_AUTHENTICATION_COMPLETED && ctx.isMfaRequiredAsPerPolicy())) {
                    ctx.changeState(MfaState.AWAITING_FACTOR_SELECTION);
                    ctx.setCurrentProcessingFactor(null); // 선택 대기이므로 현재 처리 Factor 초기화
                    ctx.setCurrentFactorOptions(null);  // 선택 대기이므로 현재 옵션 초기화
                    contextPersistence.saveContext(ctx, request);
                    log.info("MfaContinuationFilter: Allowing access to /mfa/select-factor page. Session: {}", ctx.getMfaSessionId());
                    filterChain.doFilter(request, response); // LoginController가 UI 렌더링
                } else {
                    log.warn("MfaContinuationFilter: Invalid state ({}) for accessing /mfa/select-factor. Session: {}", ctx.getCurrentState(), ctx.getMfaSessionId());
                    response.sendRedirect(contextPath + "/loginForm?error=invalid_state_for_factor_selection");
                }
                return;
            }
            else if (requestUri.startsWith(challengeUiBaseFullUrl)) {
                handleFactorChallengeUiRequest(request, response, ctx, requestUri, challengeUiBaseFullUrl, filterChain, currentMfaFlowConfig);
                return;
            }

            filterChain.doFilter(request, response);

        } catch (Exception e) {
            log.error("Error during MFA continuation processing for session {}: {}", ctx.getMfaSessionId(), e.getMessage(), e);
            if (!response.isCommitted()) {
                String mfaFailurePage = contextPath + authContextProperties.getMfa().getFailureUrl();
                response.sendRedirect(mfaFailurePage + "?error=" + "mfa_flow_exception_occurred");
            }
        }
    }

    private void handleMfaInitiation(HttpServletRequest request, HttpServletResponse response, FactorContext ctx, @Nullable AuthenticationFlowConfig flowConfig) throws IOException {
        log.info("MfaContinuationFilter: Handling MFA initiation for user: {}, Session: {}", ctx.getUsername(), ctx.getMfaSessionId());
        Assert.state(ctx.getCurrentState() == MfaState.PRIMARY_AUTHENTICATION_COMPLETED, "MFA initiation requires PRIMARY_AUTHENTICATION_COMPLETED state.");
        Assert.state(ctx.isMfaRequiredAsPerPolicy(), "MFA must be required by policy for initiation.");

        AuthType nextFactor = ctx.getCurrentProcessingFactor(); // 1차 인증 핸들러에서 이미 설정했을 수 있음
        if (nextFactor == null) {
            nextFactor = mfaPolicyProvider.determineNextFactorToProcess(ctx);
            ctx.setCurrentProcessingFactor(nextFactor);
        }

        if (nextFactor != null) {
            setFactorOptionsInContext(ctx, nextFactor, flowConfig); // Factor 옵션 설정
            log.info("MfaContinuationFilter: Next factor determined: {}. Redirecting to its challenge UI. User: {}, Session: {}", nextFactor, ctx.getUsername(), ctx.getMfaSessionId());
            ctx.changeState(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);
            contextPersistence.saveContext(ctx, request);
            response.sendRedirect(request.getContextPath() + "/mfa/challenge/" + nextFactor.name().toLowerCase());
        } else {
            log.info("MfaContinuationFilter: No specific next factor determined. Redirecting to factor selection. User: {}, Session: {}", ctx.getUsername(), ctx.getMfaSessionId());
            ctx.setCurrentProcessingFactor(null); // 선택 화면으로 가므로 현재 처리 Factor 및 옵션 초기화
            ctx.setCurrentFactorOptions(null);
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

        log.debug("MfaContinuationFilter: Handling GET request for MFA challenge UI for factor: {}. Current context factor: {}, State: {}. Session: {}",
                requestedFactor, ctx.getCurrentProcessingFactor(), ctx.getCurrentState(), ctx.getMfaSessionId());

        if (ctx.getCurrentState() != MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION ||
                ctx.getCurrentProcessingFactor() != requestedFactor) {
            log.warn("Challenge UI for factor {} requested in unexpected state ({}) or for wrong current factor (current: {}). Session: {}",
                    requestedFactor, ctx.getCurrentState(), ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + "/mfa/select-factor?error=state_mismatch_for_challenge_ui");
            return;
        }

        // FactorContext에 currentFactorOptions가 이미 설정되어 있는지 확인하고, 없다면 여기서 설정
        if (ctx.getCurrentFactorOptions() == null) {
            setFactorOptionsInContext(ctx, requestedFactor, flowConfig);
        }

        if (requestedFactor == AuthType.OTT) {
            if (emailOttService != null) {
                try {
                    emailOttService.generate(new GenerateOneTimeTokenRequest(ctx.getUsername()));
                    log.info("MFA OTT code generation requested for user {} (session {}) before rendering OTT challenge UI.", ctx.getUsername(), ctx.getMfaSessionId());
                } catch (Exception e) {
                    log.error("MfaContinuationFilter: Failed to request OTT code generation for user {} (session {}): {}", ctx.getUsername(), ctx.getMfaSessionId(), e.getMessage(), e);
                    response.sendRedirect(request.getContextPath() + "/mfa/select-factor?error=ott_send_failure");
                    return;
                }
            } else {
                log.error("EmailOneTimeTokenService is null. Cannot request OTT code generation for MFA. Session: {}", ctx.getMfaSessionId());
                responseWriter.writeErrorResponse(response, HttpStatus.INTERNAL_SERVER_ERROR.value(), "OTT_SERVICE_UNCONFIGURED", "OTT 서비스가 설정되지 않았습니다.", request.getRequestURI());
                return;
            }
        }

        ctx.changeState(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
        contextPersistence.saveContext(ctx, request);
        log.info("MfaContinuationFilter: Proceeding to render challenge UI for factor {} (session {}). New state: {}",
                requestedFactor, ctx.getMfaSessionId(), ctx.getCurrentState());
        filterChain.doFilter(request, response);
    }

    private void setFactorOptionsInContext(FactorContext ctx, AuthType factorType, @Nullable AuthenticationFlowConfig flowConfig) {
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
            ctx.setCurrentFactorOptions(null); // 명시적으로 null 설정
        }
    }

    @Nullable
    private AuthenticationFlowConfig findCurrentMfaFlowConfig() {
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            return platformConfig.getFlows().stream()
                    .filter(flow -> "mfa".equalsIgnoreCase(flow.getTypeName())) // 현재는 단일 MFA 플로우만 가정
                    .findFirst()
                    .orElse(null);
        } catch (Exception e) {
            log.error("Could not retrieve PlatformConfig or find MFA flow configuration.", e);
            return null;
        }
    }
}