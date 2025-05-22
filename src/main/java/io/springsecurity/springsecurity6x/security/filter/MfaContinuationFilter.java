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
import java.util.*;
import java.util.function.Function;

@Slf4j
public class MfaContinuationFilter extends OncePerRequestFilter {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final RequestMatcher requestMatcher;

    // 각 Matcher들은 생성자에서 최종 확정된 "대표 URL"로 초기화됨
    private final AntPathRequestMatcher mfaInitiateMatcher;
    private final AntPathRequestMatcher selectFactorMatcher;
    private final AntPathRequestMatcher ottRequestCodeUiMatcher;
    private final AntPathRequestMatcher ottChallengeMatcher;
    private final AntPathRequestMatcher passkeyChallengeMatcher;
    private final AntPathRequestMatcher tokenGeneratorMatcher;      // OTT 코드 생성 요청 (POST)
    private final AntPathRequestMatcher loginProcessingUrlMatcher;  // OTT 코드 검증 요청 (POST)

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
        if (!CollectionUtils.isEmpty(platformConfig.getFlows())) {
            mfaFlowConfig = platformConfig.getFlows().stream()
                    .filter(flow -> AuthType.MFA.name().equalsIgnoreCase(flow.getTypeName()))
                    .findFirst()
                    .orElse(null);
        }

        // 1. MFA Initiate URL (GET) - 플로우 레벨 DSL 우선, 없으면 기본값
        String determinedMfaInitiatePath = authContextProperties.getMfa().getInitiateUrl();
        this.mfaInitiateMatcher = new AntPathRequestMatcher(determinedMfaInitiatePath, HttpMethod.GET.name());

        // 2. Select Factor URL (GET) - 플로우 레벨 DSL 우선, 없으면 기본값
        String determinedSelectFactorPath = authContextProperties.getMfa().getSelectFactorUrl();
        this.selectFactorMatcher = new AntPathRequestMatcher(determinedSelectFactorPath, HttpMethod.GET.name());

        // MFA 플로우 내 OTT 관련 대표 URL (첫번째 OTT 스텝 기준)
        Optional<OttOptions> mfaFirstOttFactorOptions = getFirstMfaFactorOptionsByType(mfaFlowConfig, AuthType.OTT, OttOptions.class);

        // 3. OTT Request Code UI URL (GET) - 스텝 레벨 DSL 우선, 없으면 기본값
        String determinedOttRequestCodeUiPath = authContextProperties.getMfa().getOttFactor().getRequestCodeUiUrl();
        this.ottRequestCodeUiMatcher = new AntPathRequestMatcher(determinedOttRequestCodeUiPath, HttpMethod.GET.name());

        // 4. OTT Challenge UI URL (GET) - 스텝 레벨 DSL 우선, 없으면 기본값
        String determinedOttChallengePath = authContextProperties.getMfa().getOttFactor().getChallengeUrl();
        this.ottChallengeMatcher = new AntPathRequestMatcher(determinedOttChallengePath, HttpMethod.GET.name());

        // 5. OTT Token Generator URL (POST) - 스텝 레벨 DSL 우선, 없으면 기본값
        String determinedTokenGeneratorPath = determineUrlFromStepOptions(
                mfaFirstOttFactorOptions,
                OttOptions::getTokenGeneratingUrl,
                authContextProperties.getMfa().getOttFactor().getCodeGenerationUrl(),
                "MFA OTT token generator"
        );
        this.tokenGeneratorMatcher = new AntPathRequestMatcher(determinedTokenGeneratorPath, HttpMethod.POST.name());

        // 6. OTT Login Processing URL (POST) - 스텝 레벨 DSL 우선, 없으면 기본값
        String determinedLoginProcessingUrlPath = determineUrlFromStepOptions(
                mfaFirstOttFactorOptions,
                OttOptions::getLoginProcessingUrl,
                authContextProperties.getMfa().getOttFactor().getLoginProcessingUrl(),
                "MFA OTT login processing"
        );
        this.loginProcessingUrlMatcher = new AntPathRequestMatcher(determinedLoginProcessingUrlPath, HttpMethod.POST.name());

        // 7. Passkey Challenge UI URL (GET) - 스텝 레벨 DSL 우선, 없으면 기본값 (시큐리티 기본 경로 등)
        String determinedPasskeyChallengePath = authContextProperties.getMfa().getPasskeyFactor().getChallengeUrl();
        this.passkeyChallengeMatcher = new AntPathRequestMatcher(determinedPasskeyChallengePath, HttpMethod.GET.name());


        this.requestMatcher = new OrRequestMatcher(
                this.mfaInitiateMatcher,
                this.selectFactorMatcher,
                this.ottRequestCodeUiMatcher,
                this.ottChallengeMatcher,
                this.passkeyChallengeMatcher,
                this.tokenGeneratorMatcher,
                this.loginProcessingUrlMatcher
        );

        log.info("MfaContinuationFilter initialized. Listening on: " +
                        "GET [MFA Initiate: {}, Select Factor: {}, OTT Request UI: {}, OTT Challenge: {}, Passkey Challenge: {}], " +
                        "POST [OTT Token Generate: {}, OTT Login Process: {}]",
                determinedMfaInitiatePath, determinedSelectFactorPath, determinedOttRequestCodeUiPath, determinedOttChallengePath, determinedPasskeyChallengePath,
                determinedTokenGeneratorPath, determinedLoginProcessingUrlPath);
    }

    /**
     * 스텝 레벨 옵션 (Optional)에서 URL을 결정하는 헬퍼 메소드.
     */
    private <T_STEP_OPT extends AuthenticationProcessingOptions> String determineUrlFromStepOptions(
            Optional<T_STEP_OPT> stepOptionsOpt,
            Function<T_STEP_OPT, String> urlExtractor,
            String defaultUrl, String urlDescription) {
        String determinedUrl = defaultUrl;
        if (stepOptionsOpt.isPresent()) {
            String dslUrl = urlExtractor.apply(stepOptionsOpt.get());
            if (StringUtils.hasText(dslUrl)) {
                determinedUrl = dslUrl;
                log.debug("MfaContinuationFilter: Using {} URL from Step-Level DSL: {}", urlDescription, determinedUrl);
            }
        }
        Assert.hasText(determinedUrl, urlDescription + " URL must be configured (properties or Step DSL)");
        return determinedUrl;
    }


    private <T extends AuthenticationProcessingOptions> Optional<T> getFirstMfaFactorOptionsByType(
            @Nullable AuthenticationFlowConfig mfaFlowConfig, AuthType factorType, Class<T> optionClass) {
        if (mfaFlowConfig == null || factorType == null || CollectionUtils.isEmpty(mfaFlowConfig.getStepConfigs())) {
            return Optional.empty();
        }
        return mfaFlowConfig.getStepConfigs().stream()
                .filter(step -> factorType.name().equalsIgnoreCase(step.getType()))
                .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder))
                .flatMap(step -> getSpecificOptionFromStep(step, optionClass)); // flatMap으로 변경
    }

    private <T extends AuthenticationProcessingOptions> Optional<T> getMfaFactorOptionsByStepId(
            @Nullable AuthenticationFlowConfig mfaFlowConfig, String stepId, AuthType factorType, Class<T> optionClass) {
        if (mfaFlowConfig == null || !StringUtils.hasText(stepId) || factorType == null || CollectionUtils.isEmpty(mfaFlowConfig.getStepConfigs())) {
            return Optional.empty();
        }
        return mfaFlowConfig.getStepConfigs().stream()
                .filter(step -> stepId.equals(step.getStepId()) && factorType.name().equalsIgnoreCase(step.getType()))
                .findFirst()
                .flatMap(step -> getSpecificOptionFromStep(step, optionClass)); // flatMap으로 변경
    }

    private <T extends AuthenticationProcessingOptions> Optional<T> getSpecificOptionFromStep(AuthenticationStepConfig step, Class<T> optionClass) {
        Object optionsObj = step.getOptions().get(optionClass.getName());
        if (optionClass.isInstance(optionsObj)) {
            return Optional.of(optionClass.cast(optionsObj));
        }
        Object genericOptionsObj = step.getOptions().get("_options");
        if (optionClass.isInstance(genericOptionsObj)) {
            return Optional.of(optionClass.cast(genericOptionsObj));
        }
        // 옵션 객체를 찾지 못한 경우에도 경고보다는 trace 레벨로 로깅하거나, 호출부에서 Optional.empty()를 적절히 처리하도록 함.
        log.trace("MfaContinuationFilter(getSpecificOption): Options of type {} not found or not castable for step {} (type {}) using key {} or '_options'. Step options: {}",
                optionClass.getSimpleName(), step.getStepId(), step.getType(), optionClass.getName(), step.getOptions());
        return Optional.empty();
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
                    log.trace("MfaContinuationFilter: GET request {} matched OrRequestMatcher but no specific GET handler.", request.getRequestURI());
                    filterChain.doFilter(request, response);
                }
            }
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
                filterChain.doFilter(request, response);
            }
        } catch (Exception e) {
            handleGenericError(request, response, ctx, e);
        }
    }

    // --- GET 요청 핸들러 ---
    private void handleMfaInitiationRequest(HttpServletRequest request, HttpServletResponse response, FactorContext ctx, AuthenticationFlowConfig flowConfig) throws IOException, ServletException {
        // ... (이전과 유사, setFactorOptionsByStepIdInContext 사용) ...
        if (ctx.isMfaRequiredAsPerPolicy() &&
                (ctx.getCurrentState() == MfaState.PRIMARY_AUTHENTICATION_COMPLETED ||
                        ctx.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION ||
                        ctx.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)) {

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
                    redirectUrl = request.getContextPath() + this.ottRequestCodeUiMatcher.getPattern(); // 생성자에서 확정된 대표 UI 경로
                } else if (nextFactor == AuthType.PASSKEY) {
                    redirectUrl = request.getContextPath() + this.passkeyChallengeMatcher.getPattern(); // 생성자에서 확정된 대표 UI 경로
                } else {
                    log.warn("MFA Initiation: Unsupported initial MFA factor: {}. Redirecting to factor selection.", nextFactor);
                    redirectUrl = request.getContextPath() + this.selectFactorMatcher.getPattern();
                }
                response.sendRedirect(redirectUrl);
            } else if (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION) {
                response.sendRedirect(request.getContextPath() + this.selectFactorMatcher.getPattern());
            } else {
                log.warn("MFA Initiation: Unexpected state {} for user {}. Redirecting to factor selection.", ctx.getCurrentState(), ctx.getUsername());
                ctx.changeState(MfaState.AWAITING_FACTOR_SELECTION);
                contextPersistence.saveContext(ctx, request);
                response.sendRedirect(request.getContextPath() + this.selectFactorMatcher.getPattern());
            }
        } else {
            log.warn("MfaContinuationFilter: Invalid state ({}) or MFA not required for MFA initiation. Redirecting to login.", ctx.getCurrentState());
            response.sendRedirect(request.getContextPath() + "/loginForm?mfa_error=invalid_mfa_initiation_state");
        }
    }

    private void handleSelectFactorPageRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, FactorContext ctx) throws IOException, ServletException {
        if (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION) {
            log.info("MfaContinuationFilter: Rendering /mfa/select-factor page. Session: {}", ctx.getMfaSessionId());
            filterChain.doFilter(request, response);
        } else {
            log.warn("MfaContinuationFilter: Invalid state ({}) for /mfa/select-factor. Redirecting to MFA initiate.", ctx.getCurrentState());
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
            log.warn("MfaContinuationFilter: Invalid context for GET {}. Expected OTT in AWAITING_FACTOR_CHALLENGE_INITIATION. State: {}, Factor: {}. Redirecting.",
                    request.getRequestURI(), ctx.getCurrentState(), ctx.getCurrentProcessingFactor());
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
            log.info("MfaContinuationFilter: Rendering challenge UI for factor {} (stepId: {}, session {}). New state: {}",
                    requestedFactor, ctx.getCurrentStepId(), ctx.getMfaSessionId(), ctx.getCurrentState());
            filterChain.doFilter(request, response);
        } else {
            log.warn("Challenge UI for {} requested with invalid context: State {}, Factor {}. Redirecting.",
                    requestedFactor, ctx.getCurrentState(), ctx.getCurrentProcessingFactor());
            response.sendRedirect(request.getContextPath() + this.mfaInitiateMatcher.getPattern() + "?error=invalid_challenge_input_page_context");
        }
    }

    // --- POST 요청 핸들러 ---

    private void handleTokenGenerationRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, FactorContext ctx, AuthenticationFlowConfig flowConfig) throws IOException, ServletException {
        // 1. 요청이 tokenGeneratorMatcher에 의해 이미 일치됨 (대표 URL 기준)
        // 2. FactorContext 에서 currentStepId를 가져와야 함 (MfaPolicyProvider가 설정했어야 함)
        if (ctx.getCurrentProcessingFactor() != AuthType.OTT || !StringUtils.hasText(ctx.getCurrentStepId())) {
            log.warn("Token generation POST request for non-OTT factor or missing stepId. Factor: {}, StepId: {}, State: {}",
                    ctx.getCurrentProcessingFactor(), ctx.getCurrentStepId(), ctx.getCurrentState());
            responseWriter.writeErrorResponse(response, HttpStatus.BAD_REQUEST.value(), "","Invalid request for token generation (not OTT or missing stepId).","");
            return;
        }


        // 3. 현재 stepId에 해당하는 OttOptions (DSL 설정)를 가져옴
        Optional<OttOptions> ottOptionsForStep = getMfaFactorOptionsByStepId(flowConfig, ctx.getCurrentStepId(), AuthType.OTT, OttOptions.class);
        if(!request.getRequestURI().equals(ottOptionsForStep.get().getTokenGeneratingUrl())){
            log.warn("Token generation POST request for non-OTT factor or not matched generatorUrl. Factor: {}, StepId: {}, State: {}",
                    ctx.getCurrentProcessingFactor(), ctx.getCurrentStepId(), ctx.getCurrentState());
            responseWriter.writeErrorResponse(response, HttpStatus.BAD_REQUEST.value(), "","Token generation POST request for non-OTT factor or not matched generatorUrl","");
            return;
        }

        // 4. DSL 설정에 tokenGeneratingUrl이 명시적으로 있는지 확인 (사용자 커스텀 설정)
        if (StringUtils.hasText(ottOptionsForStep.get().getTokenGeneratingUrl())) {
            // DSL에 해당 stepId에 대한 tokenGeneratingUrl이 설정되어 있음.
            // 이 URL이 현재 요청된 URL(this.tokenGeneratorMatcher.getPattern()으로 매칭된)과 일치하는지
            // 또는 이 URL을 기반으로 MfaStepFilterWrapper가 올바른 하위 필터를 찾을 수 있는지 확인해야 함.
            // 현재는 요청된 URL이 대표 URL과 일치했고, stepId로 찾은 옵션에도 URL이 있다면 진행.
            log.info("MFA OTT (StepId: {}): Token generation requested. DSL 'tokenGeneratingUrl' found: {}",
                    ctx.getCurrentStepId(), ottOptionsForStep.get().getTokenGeneratingUrl());
            ctx.setCurrentFactorOptions(ottOptionsForStep.get()); // 현재 스텝의 정확한 옵션 설정
        } else {
            // DSL에 이 stepId에 대한 tokenGeneratingUrl이 명시적으로 설정되지 않은 경우.
            // 이 경우, 생성자에서 설정된 대표 tokenGeneratorMatcher의 URL (기본값)을 사용하는 것으로 간주.
            // 만약 "DSL로 설정한 항목에 대해서만 stepId로 체크"하고, 없으면 에러 처리하고 싶다면 여기서 return.
            // 여기서는 기본 URL을 사용하는 스텝도 이 핸들러로 들어올 수 있으므로, 옵션이 없어도 기본값으로 진행될 수 있도록
            // OttOptions가 없더라도 에러를 내지 않고, MfaStepFilterWrapper가 기본 처리 필터를 찾도록 함.
            // 단, FactorContext에 setCurrentFactorOptions는 null 또는 기본 OttOptions로 설정.
            Optional<OttOptions> defaultOttOptions = getFirstMfaFactorOptionsByType(flowConfig, AuthType.OTT, OttOptions.class);
            ctx.setCurrentFactorOptions(defaultOttOptions.orElse(null)); // 대표(첫번째) OTT 스텝 옵션 또는 null
            log.info("MFA OTT (StepId: {}): Token generation requested. No specific 'tokenGeneratingUrl' in DSL for this step. " +
                            "Proceeding with representative/default tokenGeneratorMatcher URL: {}",
                    ctx.getCurrentStepId(), this.tokenGeneratorMatcher.getPattern());
        }

        ctx.changeState(MfaState.FACTOR_CHALLENGE_SENT_AWAITING_UI);
        contextPersistence.saveContext(ctx, request);

        log.info("MfaContinuationFilter: Preparing for OTT token generation (POST for StepId: {}). Passing to MfaStepFilterWrapper.", ctx.getCurrentStepId());
        filterChain.doFilter(request, response); // MfaStepFilterWrapper로 위임
    }

    private void handleLoginProcessingRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, FactorContext ctx, AuthenticationFlowConfig flowConfig) throws IOException, ServletException {
        // 1. 요청이 loginProcessingUrlMatcher에 의해 이미 일치됨 (대표 URL 기준)
        AuthType currentFactor = ctx.getCurrentProcessingFactor();
        if ((currentFactor != AuthType.OTT && currentFactor != AuthType.PASSKEY) || !StringUtils.hasText(ctx.getCurrentStepId())) {
            log.warn("Login processing POST for unsupported factor or missing stepId. Factor: {}, StepId: {}, State: {}",
                    currentFactor, ctx.getCurrentStepId(), ctx.getCurrentState());
            responseWriter.writeErrorResponse(response, HttpStatus.BAD_REQUEST.value(), "","Invalid request for factor processing (unsupported factor or missing stepId).","");
            return;
        }
        Optional<OttOptions> ottOptionsForStep = getMfaFactorOptionsByStepId(flowConfig, ctx.getCurrentStepId(), AuthType.OTT, OttOptions.class);
        if(!request.getRequestURI().equals(ottOptionsForStep.get().getLoginProcessingUrl())){
            log.warn("Token generation POST request for non-OTT factor or not matched processingUrl. Factor: {}, StepId: {}, State: {}",
                    ctx.getCurrentProcessingFactor(), ctx.getCurrentStepId(), ctx.getCurrentState());
            responseWriter.writeErrorResponse(response, HttpStatus.BAD_REQUEST.value(), "","Token generation POST request for non-OTT factor or not matched processingUrl","");
            return;
        }
        if(ctx.getCurrentState() != MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION) {
            log.warn("Login processing POST in unexpected state: {}. Expected AWAITING_VERIFICATION. SessionId: {}", ctx.getCurrentState(), ctx.getMfaSessionId());
            responseWriter.writeErrorResponse(response, HttpStatus.INTERNAL_SERVER_ERROR.value(), "","Invalid state for factor processing.", "");
            return;
        }

        // 2. 현재 stepId에 해당하는 FactorOptions (DSL 설정)를 가져옴
        Optional<? extends AuthenticationProcessingOptions> factorOptionsForStep = Optional.empty();
        String dslConfiguredProcessingUrl = null;

        if(currentFactor == AuthType.OTT) {
            Optional<OttOptions> ottOpts = getMfaFactorOptionsByStepId(flowConfig, ctx.getCurrentStepId(), AuthType.OTT, OttOptions.class);
            if (ottOpts.isPresent()) {
                factorOptionsForStep = ottOpts;
                dslConfiguredProcessingUrl = ottOpts.get().getLoginProcessingUrl();
            }
        } else if (currentFactor == AuthType.PASSKEY) { // Passkey는 DSL로 loginProcessingUrl 설정이 없을 수 있음
            Optional<PasskeyOptions> passkeyOpts = getMfaFactorOptionsByStepId(flowConfig, ctx.getCurrentStepId(), AuthType.PASSKEY, PasskeyOptions.class);
            if (passkeyOpts.isPresent()) {
                factorOptionsForStep = passkeyOpts;
                dslConfiguredProcessingUrl = passkeyOpts.get().getLoginProcessingUrl(); // PasskeyOptions에 loginProcessingUrl이 있다면
            }
        }

        // 3. DSL 설정에 loginProcessingUrl이 명시적으로 있는지 확인
        if (factorOptionsForStep.isPresent() && StringUtils.hasText(dslConfiguredProcessingUrl)) {
            log.info("MFA {} (StepId: {}): Login processing requested. DSL 'loginProcessingUrl' found: {}",
                    currentFactor, ctx.getCurrentStepId(), dslConfiguredProcessingUrl);
            ctx.setCurrentFactorOptions(factorOptionsForStep.get());
        } else {
            // DSL에 이 stepId에 대한 loginProcessingUrl이 명시적으로 설정되지 않은 경우.
            // Passkey의 경우, DSL 설정 없이 기본 Spring Security WebAuthn URL을 사용할 수 있음.
            // OTT의 경우, 만약 DSL 설정이 필수라면 여기서 에러 처리.
            // 여기서는 기본 URL(Matcher에 설정된 대표 URL)을 사용하는 것으로 간주하고 진행.
            // MfaStepFilterWrapper가 stepId에 대한 커스텀 필터가 없으면 기본 처리 필터를 찾도록 함.
            if (currentFactor == AuthType.OTT) { // OTT는 loginProcessingUrl이 명시적으로 있어야 할 가능성이 높음
                log.warn("MFA OTT (StepId: {}): Login processing requested, but 'loginProcessingUrl' is NOT explicitly configured in DSL for this step. " +
                                "Proceeding with representative/default loginProcessingMatcher URL: {}. Ensure MfaStepFilterWrapper handles this.",
                        ctx.getCurrentStepId(), this.loginProcessingUrlMatcher.getPattern());
                // 명시적 설정이 없는 OTT 스텝에 대한 처리를 거부하고 싶다면 여기서 에러 반환
                // responseWriter.writeError(response, HttpStatus.NOT_IMPLEMENTED, "OTT Login processing not configured for this MFA step in DSL.");
                // return;
            } else if (currentFactor == AuthType.PASSKEY) {
                log.info("MFA Passkey (StepId: {}): Login processing requested. No specific 'loginProcessingUrl' in DSL for this step. " +
                                "Relying on default Passkey processing (likely Spring Security WebAuthn).",
                        ctx.getCurrentStepId());
            }
            // setCurrentFactorOptions를 null 또는 기본 옵션으로 설정
            if (factorOptionsForStep.isPresent()) { // 옵션 객체는 있지만 URL만 없는 경우
                ctx.setCurrentFactorOptions(factorOptionsForStep.get());
            } else { // 옵션 객체 자체가 없는 경우 (기본 옵션 사용 가정)
                // 대표 옵션 설정 (예: 첫번째 스텝 옵션)
                if(currentFactor == AuthType.OTT) {
                    getFirstMfaFactorOptionsByType(flowConfig, AuthType.OTT, OttOptions.class).ifPresent(ctx::setCurrentFactorOptions);
                } else if (currentFactor == AuthType.PASSKEY) {
                    getFirstMfaFactorOptionsByType(flowConfig, AuthType.PASSKEY, PasskeyOptions.class).ifPresent(ctx::setCurrentFactorOptions);
                }
            }
        }

        contextPersistence.saveContext(ctx, request);

        log.info("MfaContinuationFilter: Preparing for {} factor processing (POST for StepId: {}). Passing to MfaStepFilterWrapper.", currentFactor, ctx.getCurrentStepId());
        filterChain.doFilter(request, response); // MfaStepFilterWrapper로 위임
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
            // DSL로 특정 stepId에 대한 옵션이 명시적으로 없는 경우.
            // 이 경우, 해당 factorType의 대표 옵션 (첫번째 스텝 옵션 또는 properties 기본값 기반)을 설정할지,
            // 아니면 null로 둘지 결정해야 함. 여기서는 null로 둠.
            // MfaStepFilterWrapper에서 FactorContext의 옵션이 null일 경우 기본 처리를 하도록 유도.
            ctx.setCurrentFactorOptions(null);
            log.warn("MfaContinuationFilter: No specific options in DSL found for factor {} (StepId: {}). " +
                            "FactorContext.currentFactorOptions will be null. Relying on MfaStepFilterWrapper for default handling if applicable. User: {}",
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