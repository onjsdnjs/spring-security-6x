package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
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
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Slf4j
public class MfaContinuationFilter extends OncePerRequestFilter {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final RequestMatcher requestMatcher;

    private final AntPathRequestMatcher mfaInitiateMatcher;
    private final AntPathRequestMatcher selectFactorMatcher;
    private final AntPathRequestMatcher ottRequestCodeUiMatcher; // GET /mfa/ott/request-code-ui
    private final AntPathRequestMatcher ottChallengeMatcher;     // GET /mfa/challenge/ott
    private final AntPathRequestMatcher tokenGeneratorMatcher;     // GET /mfa/ott/generate-code
    private final AntPathRequestMatcher loginProcessingUrlMatcher;     // GET //login/mfa-ott
    private final AntPathRequestMatcher passkeyChallengeMatcher;

    public MfaContinuationFilter(ContextPersistence contextPersistence,
                                 MfaPolicyProvider mfaPolicyProvider,
                                 AuthContextProperties authContextProperties,
                                 AuthResponseWriter responseWriter,
                                 ApplicationContext applicationContext) {
        this.contextPersistence = Objects.requireNonNull(contextPersistence, "contextPersistence cannot be null");
        this.mfaPolicyProvider = Objects.requireNonNull(mfaPolicyProvider, "mfaPolicyProvider cannot be null");
        this.authContextProperties = Objects.requireNonNull(authContextProperties, "authContextProperties cannot be null");
        this.responseWriter = Objects.requireNonNull(responseWriter, "responseWriter cannot be null");
        this.applicationContext = Objects.requireNonNull(applicationContext, "applicationContext cannot be null");

        // PlatformConfig 에서 MFA 플로우 설정을 가져옴
        PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
        AuthenticationFlowConfig mfaFlowConfig = null;
        if (!CollectionUtils.isEmpty(platformConfig.getFlows())) {
            mfaFlowConfig = platformConfig.getFlows().stream()
                    .filter(flow -> AuthType.MFA.name().equalsIgnoreCase(flow.getTypeName()))
                    .findFirst()
                    .orElse(null);
        }

        // 1. MFA Initiate URL 결정 (DSL 우선)
        String mfaInitiatePath = authContextProperties.getMfa().getInitiateUrl(); // 기본값
        Assert.hasText(mfaInitiatePath, "MFA initiate URL must be configured (properties or DSL)");
        this.mfaInitiateMatcher = new AntPathRequestMatcher(mfaInitiatePath, HttpMethod.GET.name());

        // 2. Select Factor URL 결정 (DSL 우선)
        String selectFactorPath = authContextProperties.getMfa().getSelectFactorUrl(); // 기본값
        Assert.hasText(selectFactorPath, "MFA select factor URL must be configured (properties or DSL)");
        this.selectFactorMatcher = new AntPathRequestMatcher(selectFactorPath, HttpMethod.GET.name());

        // 3. OTT Request Code UI URL 결정 (MFA 플로우 내 OTT 스텝 설정 우선)
        String ottRequestCodeUiPath = authContextProperties.getMfa().getOttFactor().getRequestCodeUiUrl(); // 기본값
        Assert.hasText(ottRequestCodeUiPath, "MFA OTT request code UI URL must be configured (properties or DSL)");
        this.ottRequestCodeUiMatcher = new AntPathRequestMatcher(ottRequestCodeUiPath, HttpMethod.GET.name());

        // 4. Token Generator URL 결정 (MFA 플로우 내 OTT 스텝 설정 우선)
        String tokenGeneratorPath = authContextProperties.getMfa().getOttFactor().getCodeGenerationUrl(); // 기본값
        Optional<OttOptions> mfaOttOptions = getMfaFactorOptions(mfaFlowConfig, AuthType.OTT, OttOptions.class);
        if (mfaOttOptions.isPresent() && StringUtils.hasText(mfaOttOptions.get().getTokenGeneratingUrl())) {
            tokenGeneratorPath = mfaOttOptions.get().getTokenGeneratingUrl();
            log.info("MfaContinuationFilter: Using MFA OTT challenge URL from DSL: {}", tokenGeneratorPath);
        }
        this.tokenGeneratorMatcher = new AntPathRequestMatcher(tokenGeneratorPath, HttpMethod.GET.name());

        // 5. Ott 검증 URL 결정 (MFA 플로우 내 OTT 스텝 설정 우선)
        String loginProcessingUrlPath = authContextProperties.getMfa().getOttFactor().getLoginProcessingUrl(); // 기본값
        if (mfaOttOptions.isPresent() && StringUtils.hasText(mfaOttOptions.get().getLoginProcessingUrl())) {
            loginProcessingUrlPath = mfaOttOptions.get().getTokenGeneratingUrl();
            log.info("MfaContinuationFilter: Using MFA OTT challenge URL from DSL: {}", loginProcessingUrlPath);
        }
        this.loginProcessingUrlMatcher = new AntPathRequestMatcher(loginProcessingUrlPath, HttpMethod.GET.name());

        // 5. OTT Challenge URL 결정 (MFA 플로우 내 OTT 스텝 설정 우선)
        String ottChallengePath = authContextProperties.getMfa().getOttFactor().getChallengeUrl(); // 기본값
        Assert.hasText(ottChallengePath, "MFA OTT challenge URL must be configured (properties or DSL)");
        this.ottChallengeMatcher = new AntPathRequestMatcher(ottChallengePath, HttpMethod.GET.name());

        // 6. Passkey Challenge URL 결정 (MFA 플로우 내 Passkey 스텝 설정 우선)
        String passkeyChallengePath = authContextProperties.getMfa().getPasskeyFactor().getChallengeUrl(); // 기본값
        this.passkeyChallengeMatcher = new AntPathRequestMatcher(passkeyChallengePath, HttpMethod.GET.name());

        List<RequestMatcher> matchers = new ArrayList<>();
        matchers.add(this.mfaInitiateMatcher);
        matchers.add(this.selectFactorMatcher);
        matchers.add(this.ottRequestCodeUiMatcher);
        matchers.add(this.ottChallengeMatcher);
        matchers.add(this.tokenGeneratorMatcher);
        matchers.add(this.loginProcessingUrlMatcher);
        matchers.add(this.passkeyChallengeMatcher);

        this.requestMatcher = new OrRequestMatcher(matchers);

        log.info("MfaContinuationFilter initialized. Listening on GET requests for registered MFA UI paths.");
        log.debug("MFA Initiate Matcher: {}", mfaInitiatePath);
        log.debug("Select Factor Matcher: {}", selectFactorPath);
        log.debug("OTT Request Code UI Matcher: {}", ottRequestCodeUiPath);
        log.debug("OTT Challenge Matcher: {}", ottChallengePath);
        log.debug("OTT Code Generator Matcher: {}", tokenGeneratorPath);
        log.debug("OTT Ott Validation Matcher: {}", loginProcessingUrlPath);
    }

    /**
     * MFA 플로우 설정에서 특정 인증 타입의 첫 번째 스텝 옵션을 가져옵니다.
     * @param mfaFlowConfig MFA 플로우 설정
     * @param factorType 찾고자 하는 인증 타입
     * @param optionClass 옵션 클래스 타입
     * @return 해당 옵션 객체 (Optional)
     */
    private <T extends AuthenticationProcessingOptions> Optional<T> getMfaFactorOptions(
            @Nullable AuthenticationFlowConfig mfaFlowConfig, AuthType factorType, Class<T> optionClass) {
        if (mfaFlowConfig == null || factorType == null || CollectionUtils.isEmpty(mfaFlowConfig.getStepConfigs())) {
            return Optional.empty();
        }
        return mfaFlowConfig.getStepConfigs().stream()
                .filter(step -> factorType.name().equalsIgnoreCase(step.getType()))
                .findFirst() // 일반적으로 MFA 플로우 내에 같은 타입의 팩터는 하나만 정의될 것으로 가정
                .map(step -> {
                    // AuthenticationStepConfig의 getOptions()는 Map<String, Object>를 반환하고,
                    // 실제 옵션 객체는 특정 키로 저장되어 있다고 가정 (예: OptionClass.getName())
                    Object optionsObj = step.getOptions().get(optionClass.getName());
                    if (optionClass.isInstance(optionsObj)) {
                        return optionClass.cast(optionsObj);
                    }
                    // 또는, 스텝 자체에 옵션 객체를 직접 들고 있는 경우 (예: step.getConcreteOptions(optionClass))
                    // if (step.getConcreteOptions(optionClass) != null) return step.getConcreteOptions(optionClass);
                    return null;
                })
                .filter(Objects::nonNull);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!this.requestMatcher.matches(request) || !HttpMethod.GET.name().equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("MfaContinuationFilter processing GET request: {}", request.getRequestURI());
        FactorContext ctx = contextPersistence.contextLoad(request);

        if (ctx == null || !StringUtils.hasText(ctx.getMfaSessionId()) || !StringUtils.hasText(ctx.getFlowTypeName()) || !AuthType.MFA.name().equalsIgnoreCase(ctx.getFlowTypeName())) {
            handleInvalidContext(request, response, "MFA_SESSION_INVALID_OR_NOT_MFA_FLOW", "MFA 세션이 유효하지 않거나 MFA 플로우가 아닙니다.");
            return;
        }
        if (ctx.getCurrentState() == null || ctx.getCurrentState().isTerminal()) {
            handleTerminalContext(request, response, ctx);
            return;
        }

        AuthenticationFlowConfig currentMfaFlowConfig = findFlowConfigByName(ctx.getFlowTypeName());
        if (currentMfaFlowConfig == null) {
            handleConfigError(response, request, "MFA_FLOW_CONFIG_MISSING_CTX_MfaContFilter", "MFA 플로우 설정을 찾을 수 없습니다.");
            return;
        }

        try {
            if (mfaInitiateMatcher.matches(request)) {
                handleMfaInitiationRequest(request, response, ctx, currentMfaFlowConfig);
            } else if (selectFactorMatcher.matches(request)) {
                handleSelectFactorPageRequest(request, response, filterChain, ctx);
            } else if (ottRequestCodeUiMatcher.matches(request)) {
                // 사용자가 OTT 코드 생성을 위한 UI를 요청하는 경우
                handleMfaOttRequestCodeUiPageRequest(request, response, filterChain, ctx, currentMfaFlowConfig);
            } else if (ottChallengeMatcher.matches(request)) {
                // OTT 코드 입력 UI 요청
                handleFactorChallengeInputUiPageRequest(request, response, filterChain, ctx, AuthType.OTT, currentMfaFlowConfig);
            } else if (passkeyChallengeMatcher.matches(request)) {
                // Passkey 인증 UI 요청
                handleFactorChallengeInputUiPageRequest(request, response, filterChain, ctx, AuthType.PASSKEY, currentMfaFlowConfig);
            } else {
                filterChain.doFilter(request, response);
            }
        } catch (Exception e) {
            handleGenericError(request, response, ctx, e);
        }
    }

    private void handleMfaInitiationRequest(HttpServletRequest request, HttpServletResponse response, FactorContext ctx, AuthenticationFlowConfig flowConfig) throws IOException, ServletException {
        // MFA가 필요하고, 상태가 적절한지 확인 (1차 인증 완료, 팩터 선택 대기, 또는 챌린지 초기화 대기)
        if (ctx.isMfaRequiredAsPerPolicy() &&
                (ctx.getCurrentState() == MfaState.PRIMARY_AUTHENTICATION_COMPLETED ||
                        ctx.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION ||
                        ctx.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)) {

            log.info("MfaContinuationFilter: Guiding MFA initiation for user: {}, Session: {}, Current State: {}", ctx.getUsername(), ctx.getMfaSessionId(), ctx.getCurrentState());

            // MfaPolicyProvider를 통해 다음 진행할 Factor 및 StepId 결정. ctx의 primaryAuthentication 사용.
            mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(ctx.getPrimaryAuthentication(), ctx);
            // MfaPolicyProvider가 ctx의 currentProcessingFactor, currentStepId, currentState 등을 업데이트할 수 있음.

            if (ctx.getCurrentFactorOptions() == null && ctx.getCurrentProcessingFactor() != null) {
                setFactorOptionsInContext(ctx, ctx.getCurrentProcessingFactor(), flowConfig);
            }
            contextPersistence.saveContext(ctx, request); // 변경된 FactorContext 저장

            // 상태 및 결정된 팩터에 따라 다음 UI로 리다이렉션
            if (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION &&
                    ctx.getCurrentProcessingFactor() != null && StringUtils.hasText(ctx.getCurrentStepId())) {
                String redirectUrl;
                AuthType nextFactor = ctx.getCurrentProcessingFactor();
                if (nextFactor == AuthType.OTT) {
                    // OTT 코드 요청 UI로 리다이렉션
                    redirectUrl = request.getContextPath() + authContextProperties.getMfa().getOttFactor().getRequestCodeUiUrl();
                    log.debug("MFA Initiation: Determined OTT as next factor. Redirecting to OTT request UI: {}", redirectUrl);
                } else if (nextFactor == AuthType.PASSKEY) {
                    // Passkey 챌린지 UI로 리다이렉션
                    redirectUrl = request.getContextPath() + authContextProperties.getMfa().getPasskeyFactor().getChallengeUrl();
                    log.debug("MFA Initiation: Determined Passkey as next factor. Redirecting to Passkey challenge UI: {}", redirectUrl);
                } else {
                    log.warn("MFA Initiation: Unsupported initial MFA factor: {}. Redirecting to factor selection.", nextFactor);
                    redirectUrl = request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl();
                }
                response.sendRedirect(redirectUrl);
            } else if (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION) {
                log.debug("MFA Initiation: Redirecting to factor selection page: {}", authContextProperties.getMfa().getSelectFactorUrl());
                response.sendRedirect(request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl());
            } else {
                log.warn("MFA Initiation: Unexpected state {} after policy evaluation for user {}. Redirecting to factor selection.", ctx.getCurrentState(), ctx.getUsername());
                ctx.changeState(MfaState.AWAITING_FACTOR_SELECTION);
                contextPersistence.saveContext(ctx, request);
                response.sendRedirect(request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl());
            }
        } else {
            log.warn("MfaContinuationFilter: Invalid state ({}) or MFA not required for MFA initiation. Session: {}. Redirecting to login.", ctx.getCurrentState(), ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + "/loginForm?mfa_error=invalid_mfa_initiation_state");
        }
    }

    private void handleSelectFactorPageRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, FactorContext ctx) throws IOException, ServletException {
        if (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION) {
            log.info("MfaContinuationFilter: Rendering /mfa/select-factor page. Session: {}", ctx.getMfaSessionId());
            filterChain.doFilter(request, response); // LoginController#mfaSelectFactorPage 로 연결
        } else {
            log.warn("MfaContinuationFilter: Invalid state ({}) for /mfa/select-factor. Session: {}. Redirecting to MFA initiate.", ctx.getCurrentState(), ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + authContextProperties.getMfa().getInitiateUrl() + "?error=invalid_state_for_select_factor");
        }
    }

    /**
     * GET /mfa/ott/request-code-ui 요청을 처리합니다.
     * FactorContext를 준비하고, 실제 UI 렌더링은 LoginController로 위임합니다.
     * 이 UI에서 사용자는 폼을 통해 OTT 코드 생성을 요청하게 됩니다. (POST to codeGenerationUrl)
     */
    private void handleMfaOttRequestCodeUiPageRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, FactorContext ctx, AuthenticationFlowConfig flowConfig) throws IOException, ServletException {
        if (ctx.getCurrentProcessingFactor() == AuthType.OTT &&
                ctx.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION) {

            // StepId와 FactorOptions가 설정되어 있는지 확인 및 설정
            if (!StringUtils.hasText(ctx.getCurrentStepId())) {
                // FactorContext의 getLastCompletedFactorOrder() 사용
                Optional<AuthenticationStepConfig> ottStepOpt = findStepConfigByFactorTypeAndMinOrder(flowConfig, AuthType.OTT, ctx.getLastCompletedFactorOrder());
                ottStepOpt.ifPresentOrElse(
                        step -> ctx.setCurrentStepId(step.getStepId()),
                        () -> log.error("MFA OTT: No OTT step config found for user {}", ctx.getUsername())
                );
            }
            if (ctx.getCurrentFactorOptions() == null) {
                setFactorOptionsInContext(ctx, AuthType.OTT, flowConfig);
            }
            contextPersistence.saveContext(ctx, request); // 변경된 stepId나 options 저장

            log.info("MfaContinuationFilter: Rendering MFA OTT code request UI (GET {}). Session: {}, StepId: {}, State: {}",
                    request.getRequestURI(), ctx.getMfaSessionId(), ctx.getCurrentStepId(), ctx.getCurrentState());
            // LoginController#mfaOttRequestCodeUiPage 로 연결하여 UI 렌더링
            // 이 UI의 form action은 authContextProperties.getOttFactor().getCodeGenerationUrl() 이어야 함.
            filterChain.doFilter(request, response);

        } else {
            log.warn("MfaContinuationFilter: Invalid context for GET {}. Expected OTT factor in AWAITING_FACTOR_CHALLENGE_INITIATION state. " +
                            "Actual State: {}, Actual Factor: {}. Session: {}. Redirecting to MFA initiate.",
                    request.getRequestURI(), ctx.getCurrentState(), ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + authContextProperties.getMfa().getInitiateUrl() + "?error=invalid_ott_request_ui_context");
        }
    }

    /**
     * GET /mfa/challenge/{factorType} (예: /mfa/challenge/ott) 요청 처리.
     * 해당 팩터의 챌린지 입력 UI를 보여주기 전에 FactorContext 상태를 업데이트.
     */
    private void handleFactorChallengeInputUiPageRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, FactorContext ctx, AuthType requestedFactor, AuthenticationFlowConfig flowConfig) throws IOException, ServletException {
        // 사용자가 코드/챌린지 입력 UI에 접근했을 때 호출
        // MfaPolicyProvider 또는 OneTimeTokenCreationSuccessHandler를 통해 currentProcessingFactor와 currentState가 이미 설정되었어야 함.
        if (ctx.getCurrentProcessingFactor() == requestedFactor &&
                (ctx.getCurrentState() == MfaState.FACTOR_CHALLENGE_SENT_AWAITING_UI || // 코드 생성/발송 직후
                        ctx.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION || // 코드 생성 UI 에서 넘어왔으나 아직 코드 생성 안된 경우 (예: JS 문제로 API 호출 실패 후 직접 URL 접근)
                        ctx.getCurrentState() == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)) { // 이미 UI를 봤고, 재시도 등으로 다시 GET

            // StepId와 FactorOptions가 설정되어 있는지 확인 및 설정
            if (!StringUtils.hasText(ctx.getCurrentStepId())) {
                Optional<AuthenticationStepConfig> stepOpt = findStepConfigByFactorTypeAndMinOrder(flowConfig, requestedFactor, ctx.getLastCompletedFactorOrder());
                stepOpt.ifPresentOrElse(
                        step -> ctx.setCurrentStepId(step.getStepId()),
                        () -> log.error("No {} step config found for user {}", requestedFactor, ctx.getUsername())
                );
            }
            if (ctx.getCurrentFactorOptions() == null) {
                setFactorOptionsInContext(ctx, requestedFactor, flowConfig);
            }

            if (!StringUtils.hasText(ctx.getCurrentStepId()) || ctx.getCurrentFactorOptions() == null) {
                log.error("MfaContinuationFilter: Critical - Could not determine stepId or options for factor {} in challenge UI. Session: {}", requestedFactor, ctx.getMfaSessionId());
                response.sendRedirect(request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl() + "?error=factor_config_error_challenge_ui");
                return;
            }

            // 이 UI 페이지에 진입했으므로 상태를 "챌린지 제시됨, 검증 대기"로 변경
            ctx.changeState(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
            contextPersistence.saveContext(ctx, request);

            log.info("MfaContinuationFilter: Proceeding to render challenge input UI for factor {} (stepId: {}, session {}). New state: {}",
                    requestedFactor, ctx.getCurrentStepId(), ctx.getMfaSessionId(), ctx.getCurrentState());
            filterChain.doFilter(request, response); // LoginController의 해당 UI 렌더링 메서드로 연결
        } else {
            log.warn("Challenge UI for factor {} requested with invalid context state {} or processing factor {}. Session: {}. Redirecting to MFA initiate.",
                    requestedFactor, ctx.getCurrentState(), ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + authContextProperties.getMfa().getInitiateUrl() + "?error=invalid_challenge_input_page_context");
        }
    }

    private void handleInvalidContext(HttpServletRequest request, HttpServletResponse response, String errorCode, String errorMessage) throws IOException {
        log.warn("MfaContinuationFilter: Invalid FactorContext. ErrorCode: {}, Message: {}, Request: {}", errorCode, errorMessage, request.getRequestURI());
        contextPersistence.deleteContext(request);
        String targetUrl = UriComponentsBuilder.fromPath(request.getContextPath() + "/loginForm")
                .queryParam("mfa_error", errorCode)
                .queryParam("message", URLEncoder.encode(errorMessage, StandardCharsets.UTF_8))
                .build().toUriString();
        response.sendRedirect(targetUrl);
    }

    private void handleTerminalContext(HttpServletRequest request, HttpServletResponse response, FactorContext ctx) throws IOException {
        log.info("MfaContinuationFilter: FactorContext (ID: {}) is terminal (State: {}). Clearing context for user {}.",
                ctx.getMfaSessionId(), ctx.getCurrentState(), ctx.getUsername());
        contextPersistence.deleteContext(request);
        response.sendRedirect(request.getContextPath() + "/loginForm?mfa_error=mfa_session_already_ended");
    }
    private void handleConfigError(HttpServletResponse response, HttpServletRequest request, String errorCode, String errorMessage) throws IOException {
        log.error("MfaContinuationFilter: Configuration error. ErrorCode: {}, Message: {}, Request: {}", errorCode, errorMessage, request.getRequestURI());
        contextPersistence.deleteContext(request);
        String targetUrl = UriComponentsBuilder.fromPath(request.getContextPath() + "/loginForm")
                .queryParam("mfa_error", errorCode)
                .queryParam("message", URLEncoder.encode(errorMessage, StandardCharsets.UTF_8))
                .build().toUriString();
        response.sendRedirect(targetUrl);
    }

    private void handleGenericError(HttpServletRequest request, HttpServletResponse response, FactorContext ctx, Exception e) throws IOException {
        log.error("Error during MFA continuation for session {}: {}", (ctx != null ? ctx.getMfaSessionId() : "N/A"), e.getMessage(), e);
        if (ctx != null) {
            contextPersistence.deleteContext(request);
        }
        if (!response.isCommitted()) {
            String mfaFailurePage = request.getContextPath() + authContextProperties.getMfa().getFailureUrl();
            String errorParam = "mfa_filter_exception";
            try {
                // 너무 긴 에러 메시지는 URL 길이에 문제를 일으킬 수 있으므로 일반적인 메시지로 대체
                // errorParam = URLEncoder.encode(e.getMessage(), StandardCharsets.UTF_8);
            } catch (Exception ignored) {}
            response.sendRedirect(mfaFailurePage + "?error=" + errorParam);
        }
    }

    private void setFactorOptionsInContext(FactorContext ctx, AuthType factorType, @Nullable AuthenticationFlowConfig flowConfig) {
        if (factorType == null || flowConfig == null || flowConfig.getRegisteredFactorOptions() == null) {
            ctx.setCurrentFactorOptions(null);
            if (factorType != null) {
                log.warn("MfaContinuationFilter: Cannot set factor options. FactorType: {}, FlowConfig or RegisteredOptions are null. User: {}", factorType, ctx.getUsername());
            }
            return;
        }
        AuthenticationProcessingOptions factorOptions = flowConfig.getRegisteredFactorOptions().get(factorType);
        ctx.setCurrentFactorOptions(factorOptions);
        if (factorOptions == null) {
            log.warn("MfaContinuationFilter: No specific options found for factor {} in flow config for user {}. FactorContext.currentFactorOptions will be null.", factorType, ctx.getUsername());
        } else {
            log.debug("MfaContinuationFilter: Factor options set for factor {} in user {}'s context.", factorType, ctx.getUsername());
        }
    }

    private Optional<AuthenticationStepConfig> findStepConfigByFactorTypeAndMinOrder(AuthenticationFlowConfig flowConfig, AuthType factorType, int minOrderExclusive) {
        if (flowConfig == null || factorType == null || flowConfig.getStepConfigs() == null) {
            return Optional.empty();
        }
        return flowConfig.getStepConfigs().stream()
                .filter(step -> step.getOrder() > minOrderExclusive &&
                        factorType.name().equalsIgnoreCase(step.getType()))
                .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder));
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
                        .orElseGet(() -> {
                            log.warn("MFA Flow: No AuthenticationFlowConfig found with typeName: {}", flowTypeName);
                            return null;
                        });
            }
        } catch (Exception e) {
            log.warn("MfaContinuationFilter: Error retrieving PlatformConfig or flow configuration for type {}: {}", flowTypeName, e.getMessage());
        }
        return null;
    }
}