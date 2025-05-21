package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;
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
import org.springframework.http.HttpStatus;
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
import java.util.Comparator;
import java.util.Objects;
import java.util.Optional;

@Slf4j
public class MfaContinuationFilter extends OncePerRequestFilter {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final RequestMatcher requestMatcher;

    // UI 경로 Matcher (GET)
    private final AntPathRequestMatcher mfaInitiateMatcher;
    private final AntPathRequestMatcher selectFactorMatcher;
    private final AntPathRequestMatcher ottRequestCodeUiMatcher;
    private final AntPathRequestMatcher ottChallengeMatcher;
    private final AntPathRequestMatcher passkeyChallengeMatcher;

    // API 및 인증 처리 경로 Matcher (주로 POST, 이 필터는 요청을 인지하고 다음 필터로 넘기는 역할)
    private final AntPathRequestMatcher tokenGeneratorMatcher;
    private final AntPathRequestMatcher loginProcessingUrlMatcher;

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

        PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
        AuthenticationFlowConfig mfaFlowConfig = null;
        if (platformConfig != null && !CollectionUtils.isEmpty(platformConfig.getFlows())) {
            mfaFlowConfig = platformConfig.getFlows().stream()
                    .filter(flow -> AuthType.MFA.name().equalsIgnoreCase(flow.getTypeName()))
                    .findFirst()
                    .orElse(null);
        }

        // --- GET 요청 기반 UI 경로 Matcher 초기화 ---
        String mfaInitiatePath = authContextProperties.getMfa().getInitiateUrl();
        Assert.hasText(mfaInitiatePath, "MFA initiate URL must be configured");
        this.mfaInitiateMatcher = new AntPathRequestMatcher(mfaInitiatePath, HttpMethod.GET.name());

        String selectFactorPath = authContextProperties.getMfa().getSelectFactorUrl();
        Assert.hasText(selectFactorPath, "MFA select factor URL must be configured");
        this.selectFactorMatcher = new AntPathRequestMatcher(selectFactorPath, HttpMethod.GET.name());

        Optional<OttOptions> mfaFirstOttFactorOptions = getFirstMfaFactorOptionsByType(mfaFlowConfig, AuthType.OTT, OttOptions.class);
        String ottRequestCodeUiPath = authContextProperties.getMfa().getOttFactor().getRequestCodeUiUrl();
        Assert.hasText(ottRequestCodeUiPath, "MFA OTT request code UI URL must be configured");
        this.ottRequestCodeUiMatcher = new AntPathRequestMatcher(ottRequestCodeUiPath, HttpMethod.GET.name());

        String ottChallengePath = authContextProperties.getMfa().getOttFactor().getChallengeUrl();
        Assert.hasText(ottChallengePath, "MFA OTT challenge URL must be configured");
        this.ottChallengeMatcher = new AntPathRequestMatcher(ottChallengePath, HttpMethod.GET.name());

        Optional<PasskeyOptions> mfaPasskeyFactorOptions = getFirstMfaFactorOptionsByType(mfaFlowConfig, AuthType.PASSKEY, PasskeyOptions.class);
        String passkeyChallengePath = authContextProperties.getMfa().getPasskeyFactor().getChallengeUrl();
        Assert.hasText(passkeyChallengePath, "MFA Passkey challenge URL must be configured");
        this.passkeyChallengeMatcher = new AntPathRequestMatcher(passkeyChallengePath, HttpMethod.GET.name());

        // --- POST 요청 기반 API/처리 경로 Matcher 초기화 (대표 URL 사용) ---
        String tokenGeneratorPath = authContextProperties.getMfa().getOttFactor().getCodeGenerationUrl();
        if (mfaFirstOttFactorOptions.isPresent() && StringUtils.hasText(mfaFirstOttFactorOptions.get().getTokenGeneratingUrl())) {
            tokenGeneratorPath = mfaFirstOttFactorOptions.get().getTokenGeneratingUrl();
        }
        Assert.hasText(tokenGeneratorPath, "MFA OTT token generator URL must be configured");
        this.tokenGeneratorMatcher = new AntPathRequestMatcher(tokenGeneratorPath, HttpMethod.POST.name());

        String loginProcessingUrlPath = authContextProperties.getMfa().getOttFactor().getLoginProcessingUrl();
        if (mfaFirstOttFactorOptions.isPresent() && StringUtils.hasText(mfaFirstOttFactorOptions.get().getLoginProcessingUrl())) {
            loginProcessingUrlPath = mfaFirstOttFactorOptions.get().getLoginProcessingUrl();
        }
        Assert.hasText(loginProcessingUrlPath, "MFA OTT login processing URL must be configured");
        this.loginProcessingUrlMatcher = new AntPathRequestMatcher(loginProcessingUrlPath, HttpMethod.POST.name());


        this.requestMatcher = new OrRequestMatcher(
                this.mfaInitiateMatcher,          // GET
                this.selectFactorMatcher,         // GET
                this.ottRequestCodeUiMatcher,     // GET
                this.ottChallengeMatcher,         // GET
                this.passkeyChallengeMatcher,     // GET
                this.tokenGeneratorMatcher,       // POST
                this.loginProcessingUrlMatcher    // POST
        );

        log.info("MfaContinuationFilter initialized. Listening on UI (GET) and API/Processing (POST) paths.");
        log.debug("MFA UI Paths (GET): Initiate [{}], Select Factor [{}], OTT Request UI [{}], OTT Challenge [{}], Passkey Challenge [{}]",
                mfaInitiatePath, selectFactorPath, ottRequestCodeUiPath, ottChallengePath, passkeyChallengePath);
        log.debug("MFA API/Processing Paths (POST): OTT Token Generate [{}], OTT Login Process [{}]",
                tokenGeneratorPath, loginProcessingUrlPath);
    }

    /**
     * MFA 플로우 설정에서 특정 인증 타입의 첫 번째 스텝 옵션을 가져옵니다.
     * 이 메소드는 필터 생성 시점에서 각 경로의 대표 URL을 설정하기 위해 사용됩니다.
     */
    private <T extends AuthenticationProcessingOptions> Optional<T> getFirstMfaFactorOptionsByType(
            @Nullable AuthenticationFlowConfig mfaFlowConfig, AuthType factorType, Class<T> optionClass) {
        if (mfaFlowConfig == null || factorType == null || CollectionUtils.isEmpty(mfaFlowConfig.getStepConfigs())) {
            return Optional.empty();
        }
        return mfaFlowConfig.getStepConfigs().stream()
                .filter(step -> factorType.name().equalsIgnoreCase(step.getType()))
                .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder))
                .map(step -> {
                    // AuthenticationStepConfig의 getOptions()는 Map<String, Object>를 반환하고,
                    // 실제 옵션 객체는 optionClass의 이름(또는 다른 약속된 키)으로 저장되어 있다고 가정
                    Object optionsObj = step.getOptions().get(optionClass.getName());
                    if (optionClass.isInstance(optionsObj)) {
                        return optionClass.cast(optionsObj);
                    }
                    // 대체 키 "_options" 시도 (구현에 따라 다를 수 있음)
                    Object genericOptionsObj = step.getOptions().get("_options");
                    if (optionClass.isInstance(genericOptionsObj)) {
                        return optionClass.cast(genericOptionsObj);
                    }
                    log.warn("MfaContinuationFilter(getFirst): Could not find or cast options of type {} for step {} (type {}) using key {} or '_options'. Step options: {}",
                            optionClass.getSimpleName(), step.getStepId(), step.getType(), optionClass.getName(), step.getOptions());
                    return null;
                })
                .filter(Objects::nonNull);
    }

    /**
     * MFA 플로우 설정에서 특정 stepId와 factorType에 해당하는 스텝의 옵션을 가져옵니다.
     * 이 메소드는 doFilterInternal 내에서 현재 진행 중인 스텝의 구체적인 설정을 가져올 때 사용됩니다.
     */
    private <T extends AuthenticationProcessingOptions> Optional<T> getMfaFactorOptionsByStepId(
            @Nullable AuthenticationFlowConfig mfaFlowConfig, String stepId, AuthType factorType, Class<T> optionClass) {
        if (mfaFlowConfig == null || !StringUtils.hasText(stepId) || factorType == null || CollectionUtils.isEmpty(mfaFlowConfig.getStepConfigs())) {
            return Optional.empty();
        }
        return mfaFlowConfig.getStepConfigs().stream()
                .filter(step -> stepId.equals(step.getStepId()) && factorType.name().equalsIgnoreCase(step.getType()))
                .findFirst()
                .map(step -> {
                    Object optionsObj = step.getOptions().get("_options");
                    if (optionClass.isInstance(optionsObj)) {
                        return optionClass.cast(optionsObj);
                    }
                    Object genericOptionsObj = step.getOptions().get("_options"); // 대체 키 시도
                    if (optionClass.isInstance(genericOptionsObj)) {
                        return optionClass.cast(genericOptionsObj);
                    }
                    log.warn("MfaContinuationFilter(getByStepId): Could not find or cast options of type {} for step {} (type {}) using key {} or '_options'. Step options: {}",
                            optionClass.getSimpleName(), step.getStepId(), step.getType(), optionClass.getName(), step.getOptions());
                    return null;
                })
                .filter(Objects::nonNull);
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!this.requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("MfaContinuationFilter processing request: {} {}", request.getMethod(), request.getRequestURI());
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
            // --- GET 요청 처리 (UI 페이지 안내 또는 렌더링 위임) ---
            if (HttpMethod.GET.name().equalsIgnoreCase(request.getMethod())) {
                if (mfaInitiateMatcher.matches(request)) {
                    handleMfaInitiationRequest(request, response, ctx, currentMfaFlowConfig);
                } else if (selectFactorMatcher.matches(request)) {
                    handleSelectFactorPageRequest(request, response, filterChain, ctx);
                } else if (ottRequestCodeUiMatcher.matches(request)) {
                    handleMfaOttRequestCodeUiPageRequest(request, response, filterChain, ctx, currentMfaFlowConfig);
                } else if (ottChallengeMatcher.matches(request)) {
                    handleFactorChallengeInputUiPageRequest(request, response, filterChain, ctx, AuthType.OTT, currentMfaFlowConfig);
                } else if (passkeyChallengeMatcher.matches(request)) {
                    handleFactorChallengeInputUiPageRequest(request, response, filterChain, ctx, AuthType.PASSKEY, currentMfaFlowConfig);
                } else {
                    // OrRequestMatcher에 의해 매칭되었으나, GET 핸들러가 없는 경우 (이론상 POST 매칭)
                    log.debug("MfaContinuationFilter: GET request {} matched OrRequestMatcher but no specific GET handler. Passing to next filter (likely for POST).", request.getRequestURI());
                    filterChain.doFilter(request, response);
                }
            }
            // --- POST 요청 처리 (API 및 인증 처리 - MfaStepFilterWrapper로 위임 준비) ---
            else if (HttpMethod.POST.name().equalsIgnoreCase(request.getMethod())) {
                if (tokenGeneratorMatcher.matches(request)) {
                    handleTokenGenerationRequest(request, response, filterChain, ctx, currentMfaFlowConfig);
                } else if (loginProcessingUrlMatcher.matches(request)) {
                    handleLoginProcessingRequest(request, response, filterChain, ctx, currentMfaFlowConfig);
                } else {
                    log.warn("MfaContinuationFilter: POST request {} matched OrRequestMatcher but not any specific POST handler.", request.getRequestURI());
                    filterChain.doFilter(request, response);
                }
            } else {
                // 기타 HTTP 메소드 (PUT, DELETE 등) - 이 필터에서 처리 안 함
                filterChain.doFilter(request, response);
            }
        } catch (Exception e) {
            handleGenericError(request, response, ctx, e);
        }
    }

    // --- GET 요청 핸들러들 (UI 안내 및 렌더링 위임) ---

    private void handleMfaInitiationRequest(HttpServletRequest request, HttpServletResponse response, FactorContext ctx, AuthenticationFlowConfig flowConfig) throws IOException, ServletException {
        if (ctx.isMfaRequiredAsPerPolicy() &&
                (ctx.getCurrentState() == MfaState.PRIMARY_AUTHENTICATION_COMPLETED ||
                        ctx.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION ||
                        ctx.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)) {

            log.info("MfaContinuationFilter: Guiding MFA initiation for user: {}, Session: {}, Current State: {}", ctx.getUsername(), ctx.getMfaSessionId(), ctx.getCurrentState());
            mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(ctx.getPrimaryAuthentication(), ctx);

            if (StringUtils.hasText(ctx.getCurrentStepId()) && ctx.getCurrentProcessingFactor() != null && ctx.getCurrentFactorOptions() == null) {
                setFactorOptionsByStepIdInContext(ctx, ctx.getCurrentProcessingFactor(), ctx.getCurrentStepId(), flowConfig);
            }
            contextPersistence.saveContext(ctx, request);

            if (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION &&
                    ctx.getCurrentProcessingFactor() != null && StringUtils.hasText(ctx.getCurrentStepId())) {
                String redirectUrl;
                AuthType nextFactor = ctx.getCurrentProcessingFactor();

                if (nextFactor == AuthType.OTT) {
                    redirectUrl = request.getContextPath() + this.ottRequestCodeUiMatcher.getPattern();
                } else if (nextFactor == AuthType.PASSKEY) {
                    redirectUrl = request.getContextPath() + this.passkeyChallengeMatcher.getPattern();
                } else {
                    log.warn("MFA Initiation: Unsupported initial MFA factor: {}. Redirecting to factor selection.", nextFactor);
                    redirectUrl = request.getContextPath() + this.selectFactorMatcher.getPattern();
                }
                response.sendRedirect(redirectUrl);
            } else if (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION) {
                response.sendRedirect(request.getContextPath() + this.selectFactorMatcher.getPattern());
            } else {
                log.warn("MFA Initiation: Unexpected state {} after policy evaluation for user {}. Redirecting to factor selection.", ctx.getCurrentState(), ctx.getUsername());
                ctx.changeState(MfaState.AWAITING_FACTOR_SELECTION);
                contextPersistence.saveContext(ctx, request);
                response.sendRedirect(request.getContextPath() + this.selectFactorMatcher.getPattern());
            }
        } else {
            log.warn("MfaContinuationFilter: Invalid state ({}) or MFA not required for MFA initiation. Session: {}. Redirecting to login.", ctx.getCurrentState(), ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + "/loginForm?mfa_error=invalid_mfa_initiation_state");
        }
    }

    private void handleSelectFactorPageRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, FactorContext ctx) throws IOException, ServletException {
        if (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION) {
            log.info("MfaContinuationFilter: Rendering /mfa/select-factor page. Session: {}", ctx.getMfaSessionId());
            filterChain.doFilter(request, response);
        } else {
            log.warn("MfaContinuationFilter: Invalid state ({}) for /mfa/select-factor. Session: {}. Redirecting to MFA initiate.", ctx.getCurrentState(), ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + this.mfaInitiateMatcher.getPattern() + "?error=invalid_state_for_select_factor");
        }
    }

    private void handleMfaOttRequestCodeUiPageRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, FactorContext ctx, AuthenticationFlowConfig flowConfig) throws IOException, ServletException {
        if (ctx.getCurrentProcessingFactor() == AuthType.OTT &&
                ctx.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION) {

            if (StringUtils.hasText(ctx.getCurrentStepId()) && ctx.getCurrentFactorOptions() == null) {
                setFactorOptionsByStepIdInContext(ctx, AuthType.OTT, ctx.getCurrentStepId(), flowConfig);
            } else if (!StringUtils.hasText(ctx.getCurrentStepId())) {
                Optional<AuthenticationStepConfig> ottStepOpt = findStepConfigByFactorTypeAndMinOrder(flowConfig, AuthType.OTT, ctx.getLastCompletedFactorOrder());
                ottStepOpt.ifPresentOrElse(
                        step -> {
                            ctx.setCurrentStepId(step.getStepId());
                            setFactorOptionsByStepIdInContext(ctx, AuthType.OTT, step.getStepId(), flowConfig);
                        },
                        () -> log.error("MFA OTT Request UI: No OTT step config found for user {}", ctx.getUsername())
                );
            }
            contextPersistence.saveContext(ctx, request);
            log.info("MfaContinuationFilter: Rendering MFA OTT code request UI (GET {}). Session: {}, StepId: {}, State: {}",
                    request.getRequestURI(), ctx.getMfaSessionId(), ctx.getCurrentStepId(), ctx.getCurrentState());
            filterChain.doFilter(request, response);
        } else {
            log.warn("MfaContinuationFilter: Invalid context for GET {}. Expected OTT factor in AWAITING_FACTOR_CHALLENGE_INITIATION state. " +
                            "Actual State: {}, Actual Factor: {}. Session: {}. Redirecting to MFA initiate.",
                    request.getRequestURI(), ctx.getCurrentState(), ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + this.mfaInitiateMatcher.getPattern() + "?error=invalid_ott_request_ui_context");
        }
    }

    private void handleFactorChallengeInputUiPageRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, FactorContext ctx, AuthType requestedFactor, AuthenticationFlowConfig flowConfig) throws IOException, ServletException {
        if (ctx.getCurrentProcessingFactor() == requestedFactor &&
                (ctx.getCurrentState() == MfaState.FACTOR_CHALLENGE_SENT_AWAITING_UI ||
                        ctx.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION ||
                        ctx.getCurrentState() == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)) {

            if (StringUtils.hasText(ctx.getCurrentStepId()) && ctx.getCurrentFactorOptions() == null) {
                setFactorOptionsByStepIdInContext(ctx, requestedFactor, ctx.getCurrentStepId(), flowConfig);
            } else if (!StringUtils.hasText(ctx.getCurrentStepId())) {
                Optional<AuthenticationStepConfig> stepOpt = findStepConfigByFactorTypeAndMinOrder(flowConfig, requestedFactor, ctx.getLastCompletedFactorOrder());
                stepOpt.ifPresentOrElse(
                        step -> {
                            ctx.setCurrentStepId(step.getStepId());
                            setFactorOptionsByStepIdInContext(ctx, requestedFactor, step.getStepId(), flowConfig);
                        },
                        () -> log.error("MFA Challenge UI: No {} step config found for user {}", requestedFactor, ctx.getUsername())
                );
            }

            if (!StringUtils.hasText(ctx.getCurrentStepId()) || ctx.getCurrentFactorOptions() == null) {
                log.error("MfaContinuationFilter: Critical - Could not determine stepId or options for factor {} in challenge UI. Session: {}", requestedFactor, ctx.getMfaSessionId());
                response.sendRedirect(request.getContextPath() + this.selectFactorMatcher.getPattern() + "?error=factor_config_error_challenge_ui");
                return;
            }
            ctx.changeState(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
            contextPersistence.saveContext(ctx, request);
            log.info("MfaContinuationFilter: Proceeding to render challenge input UI for factor {} (stepId: {}, session {}). New state: {}",
                    requestedFactor, ctx.getCurrentStepId(), ctx.getMfaSessionId(), ctx.getCurrentState());
            filterChain.doFilter(request, response);
        } else {
            log.warn("Challenge UI for factor {} requested with invalid context state {} or processing factor {}. Session: {}. Redirecting to MFA initiate.",
                    requestedFactor, ctx.getCurrentState(), ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + this.mfaInitiateMatcher.getPattern() + "?error=invalid_challenge_input_page_context");
        }
    }

    // --- POST 요청 핸들러들 (MfaStepFilterWrapper로 처리 위임 준비) ---

    private void handleTokenGenerationRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, FactorContext ctx, AuthenticationFlowConfig flowConfig) throws IOException, ServletException {
        if (ctx.getCurrentProcessingFactor() != AuthType.OTT) {
            log.warn("Token generation requested for non-OTT factor or invalid context. Factor: {}, State: {}", ctx.getCurrentProcessingFactor(), ctx.getCurrentState());
            responseWriter.writeErrorResponse(response, HttpStatus.BAD_REQUEST.value(), "","Invalid request for token generation.","");
            return;
        }
        if (!StringUtils.hasText(ctx.getCurrentStepId())) {
            log.error("Token generation requested but currentStepId is missing in FactorContext. SessionId: {}", ctx.getMfaSessionId());
            responseWriter.writeErrorResponse(response, HttpStatus.BAD_REQUEST.value(), "","MFA context is incomplete (missing stepId).","");
            return;
        }

        // 현재 stepId에 해당하는 OttOptions 가져오기
        Optional<OttOptions> ottOptions = getMfaFactorOptionsByStepId(flowConfig, ctx.getCurrentStepId(), AuthType.OTT, OttOptions.class);
        if (ottOptions.isEmpty() || !StringUtils.hasText(ottOptions.get().getTokenGeneratingUrl())) {
            log.error("Token generation URL not configured for OTT stepId: {} in MFA flow.", ctx.getCurrentStepId());
            responseWriter.writeErrorResponse(response, HttpStatus.INTERNAL_SERVER_ERROR.value(), "","Token generation not configured for this MFA step.", ottOptions.get().getTokenGeneratingUrl());
            return;
        }

        // MfaPolicyProvider가 stepId를 설정하고, 여기서는 해당 stepId의 옵션을 사용함을 확인.
        // 실제 코드 생성은 MfaStepFilterWrapper를 통해 위임될 전용 필터 (예: OttCodeGenerationFilter)가 수행.
        // 이 필터는 상태 변경 및 컨텍스트 저장 후 다음 필터로 넘김.
        ctx.changeState(MfaState.FACTOR_CHALLENGE_SENT_AWAITING_UI); // 코드 생성 요청 시작 상태
        ctx.setCurrentFactorOptions(ottOptions.get()); // 현재 스텝의 정확한 옵션 설정
        contextPersistence.saveContext(ctx, request);

        log.info("MfaContinuationFilter: Preparing for OTT token generation. FactorContext updated for stepId: {}. Passing to MfaStepFilterWrapper.", ctx.getCurrentStepId());
        filterChain.doFilter(request, response); // MfaStepFilterWrapper가 이 요청을 받아 처리하도록 함
    }

    private void handleLoginProcessingRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, FactorContext ctx, AuthenticationFlowConfig flowConfig) throws IOException, ServletException {
        if (ctx.getCurrentProcessingFactor() != AuthType.OTT && ctx.getCurrentProcessingFactor() != AuthType.PASSKEY) { // 다른 팩터 타입 추가 가능
            log.warn("Login processing requested for unsupported factor or invalid context. Factor: {}, State: {}", ctx.getCurrentProcessingFactor(), ctx.getCurrentState());
            responseWriter.writeErrorResponse(response, HttpStatus.BAD_REQUEST.value(), "", "Invalid request for factor processing.", "");
            return;
        }
        if (!StringUtils.hasText(ctx.getCurrentStepId())) {
            log.error("Login processing requested but currentStepId is missing in FactorContext. SessionId: {}", ctx.getMfaSessionId());
            responseWriter.writeErrorResponse(response, HttpStatus.BAD_REQUEST.value(), "", "MFA context is incomplete (missing stepId).", "");
            return;
        }
        if(ctx.getCurrentState() != MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION) {
            log.warn("Login processing requested in an unexpected state: {}. Expected AWAITING_VERIFICATION. SessionId: {}", ctx.getCurrentState(), ctx.getMfaSessionId());
            // 상태에 따라 다른 처리 또는 에러 응답
        }

        // 현재 stepId에 해당하는 FactorOptions 가져오기
        Optional<? extends AuthenticationProcessingOptions> factorOptions = Optional.empty();
        if(ctx.getCurrentProcessingFactor() == AuthType.OTT) {
            factorOptions = getMfaFactorOptionsByStepId(flowConfig, ctx.getCurrentStepId(), AuthType.OTT, OttOptions.class);
        } else if (ctx.getCurrentProcessingFactor() == AuthType.PASSKEY) {
            factorOptions = getMfaFactorOptionsByStepId(flowConfig, ctx.getCurrentStepId(), AuthType.PASSKEY, PasskeyOptions.class);
        }

        if (factorOptions.isEmpty() || (ctx.getCurrentProcessingFactor() == AuthType.OTT && !StringUtils.hasText(((OttOptions)factorOptions.get()).getLoginProcessingUrl()))
                || (ctx.getCurrentProcessingFactor() == AuthType.PASSKEY && !StringUtils.hasText(((PasskeyOptions)factorOptions.get()).getLoginProcessingUrl())) ) { // PasskeyOptions의 loginProcessingUrl 확인
            log.error("Login processing URL not configured for {} stepId: {} in MFA flow.",ctx.getCurrentProcessingFactor(), ctx.getCurrentStepId());
            responseWriter.writeErrorResponse(response, HttpStatus.INTERNAL_SERVER_ERROR.value(), "","Factor processing not configured for this MFA step","");
            return;
        }
        ctx.setCurrentFactorOptions(factorOptions.get()); // 현재 스텝의 정확한 옵션 설정

        // 상태는 MfaStepFilterWrapper 또는 그 하위 필터에서 인증 성공/실패에 따라 변경됨.
        // 이 필터는 컨텍스트 준비 후 다음 필터로 넘김.
        contextPersistence.saveContext(ctx, request);

        log.info("MfaContinuationFilter: Preparing for {} factor processing. FactorContext updated for stepId: {}. Passing to MfaStepFilterWrapper.", ctx.getCurrentProcessingFactor(), ctx.getCurrentStepId());
        filterChain.doFilter(request, response); // MfaStepFilterWrapper가 이 요청을 받아 처리하도록 함
    }

    // --- 공통 에러 핸들러 및 유틸리티 메소드 ---

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
            response.sendRedirect(mfaFailurePage + "?error=" + errorParam);
        }
    }

    /**
     * FactorContext에 현재 진행 중인 스텝(stepId 기준)의 옵션을 설정합니다.
     */
    private void setFactorOptionsByStepIdInContext(FactorContext ctx, AuthType factorType, String stepId, @Nullable AuthenticationFlowConfig flowConfig) {
        if (factorType == null || !StringUtils.hasText(stepId) || flowConfig == null) {
            ctx.setCurrentFactorOptions(null);
            log.warn("MfaContinuationFilter: Cannot set factor options by stepId. Missing info. FactorType: {}, StepId: {}, FlowConfig is null: {}. User: {}",
                    factorType, stepId, (flowConfig == null), ctx.getUsername());
            return;
        }

        Optional<? extends AuthenticationProcessingOptions> factorOptionsOpt = Optional.empty();
        if (factorType == AuthType.OTT) {
            factorOptionsOpt = getMfaFactorOptionsByStepId(flowConfig, stepId, AuthType.OTT, OttOptions.class);
        } else if (factorType == AuthType.PASSKEY) {
            factorOptionsOpt = getMfaFactorOptionsByStepId(flowConfig, stepId, AuthType.PASSKEY, PasskeyOptions.class);
        }

        if (factorOptionsOpt.isPresent()) {
            ctx.setCurrentFactorOptions(factorOptionsOpt.get());
            log.debug("MfaContinuationFilter: Factor options set for factor {} (StepId: {}) in user {}'s context.",
                    factorType, stepId, ctx.getUsername());
        } else {
            ctx.setCurrentFactorOptions(null);
            log.warn("MfaContinuationFilter: No specific options found for factor {} (StepId: {}) in MFA flow config for user {}. FactorContext.currentFactorOptions will be null.",
                    factorType, stepId, ctx.getUsername());
        }
    }


    private Optional<AuthenticationStepConfig> findStepConfigByFactorTypeAndMinOrder(AuthenticationFlowConfig flowConfig, AuthType factorType, int minOrderExclusive) {
        if (flowConfig == null || factorType == null || CollectionUtils.isEmpty(flowConfig.getStepConfigs())) {
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
            if (platformConfig != null && !CollectionUtils.isEmpty(platformConfig.getFlows())) {
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