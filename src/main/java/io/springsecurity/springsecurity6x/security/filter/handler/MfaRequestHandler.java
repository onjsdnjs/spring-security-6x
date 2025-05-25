package io.springsecurity.springsecurity6x.security.filter.handler;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.filter.matcher.MfaRequestType;
import io.springsecurity.springsecurity6x.security.filter.matcher.MfaUrlMatcher;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static io.springsecurity.springsecurity6x.security.filter.matcher.MfaRequestType.MFA_INITIATE;

@Slf4j
@RequiredArgsConstructor
public class MfaRequestHandler {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final MfaUrlMatcher urlMatcher;

    public void handle(MfaRequestType requestType, HttpServletRequest request, HttpServletResponse response,
                       FactorContext ctx, AuthenticationFlowConfig flowConfig, FilterChain chain)
            throws IOException, ServletException {

        switch (requestType) {
            case MFA_INITIATE:
                handleMfaInitiationRequest(request, response, ctx, flowConfig);
                break;
            case SELECT_FACTOR:
                handleSelectFactorPageRequest(request, response, chain, ctx);
                break;
            case OTT_REQUEST_UI:
                handleMfaOttRequestCodeUiPageRequest(request, response, chain, ctx, flowConfig);
                break;
            case OTT_CHALLENGE:
                handleFactorChallengeInputUiPageRequest(request, response, chain, ctx, AuthType.OTT, flowConfig);
                break;
            case PASSKEY_CHALLENGE:
                handleFactorChallengeInputUiPageRequest(request, response, chain, ctx, AuthType.PASSKEY, flowConfig);
                break;
            case TOKEN_GENERATION:
                handleTokenGenerationRequest(request, response, chain, ctx, flowConfig);
                break;
            case LOGIN_PROCESSING:
                handleLoginProcessingRequest(request, response, chain, ctx, flowConfig);
                break;
            default:
                chain.doFilter(request, response);
        }
    }

    private void handleMfaInitiationRequest(HttpServletRequest request, HttpServletResponse response,
                                            FactorContext ctx, AuthenticationFlowConfig flowConfig)
            throws IOException {
        if (!ctx.isMfaRequiredAsPerPolicy() || !isValidInitiationState(ctx.getCurrentState())) {
            log.warn("Invalid state for MFA initiation. State: {}, MFA Required: {}",
                    ctx.getCurrentState(), ctx.isMfaRequiredAsPerPolicy());
            response.sendRedirect(request.getContextPath() + "/loginForm?mfa_error=invalid_mfa_initiation_state");
            return;
        }

        mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(ctx.getPrimaryAuthentication(), ctx);

        if (StringUtils.hasText(ctx.getCurrentStepId()) && ctx.getCurrentProcessingFactor() != null &&
                ctx.getCurrentFactorOptions() == null) {
            setFactorOptionsByStepIdInContext(ctx, ctx.getCurrentProcessingFactor(), ctx.getCurrentStepId(), flowConfig);
        }

        contextPersistence.saveContext(ctx, request);

        String redirectUrl = determineRedirectUrl(request, ctx);
        response.sendRedirect(redirectUrl);
    }

    private boolean isValidInitiationState(MfaState state) {
        return state == MfaState.PRIMARY_AUTHENTICATION_COMPLETED ||
                state == MfaState.AWAITING_FACTOR_SELECTION ||
                state == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION;
    }

    private String determineRedirectUrl(HttpServletRequest request, FactorContext ctx) {
        MfaState state = ctx.getCurrentState();
        String contextPath = request.getContextPath();

        if (state == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION &&
                ctx.getCurrentProcessingFactor() != null &&
                StringUtils.hasText(ctx.getCurrentStepId())) {

            AuthType factor = ctx.getCurrentProcessingFactor();
            return switch (factor) {
                case OTT -> contextPath + authContextProperties.getMfa().getOttFactor().getRequestCodeUiUrl();
                case PASSKEY -> contextPath + authContextProperties.getMfa().getPasskeyFactor().getChallengeUrl();
                default -> {
                    log.warn("Unsupported MFA factor: {}. Redirecting to factor selection.", factor);
                    yield contextPath + authContextProperties.getMfa().getSelectFactorUrl();
                }
            };
        }

        return contextPath + authContextProperties.getMfa().getSelectFactorUrl();
    }

    private void handleSelectFactorPageRequest(HttpServletRequest request, HttpServletResponse response,
                                               FilterChain chain, FactorContext ctx)
            throws IOException, ServletException {
        if (ctx.getCurrentState() != MfaState.AWAITING_FACTOR_SELECTION) {
            log.warn("Invalid state for factor selection: {}", ctx.getCurrentState());
            response.sendRedirect(request.getContextPath() + urlMatcher.getMfaInitiateUrl() +
                    "?error=invalid_state_for_select_factor");
            return;
        }

        log.info("Rendering factor selection page for session: {}", ctx.getMfaSessionId());
        chain.doFilter(request, response);
    }

    private void handleMfaOttRequestCodeUiPageRequest(HttpServletRequest request, HttpServletResponse response,
                                                      FilterChain chain, FactorContext ctx,
                                                      AuthenticationFlowConfig flowConfig)
            throws IOException, ServletException {
        if (ctx.getCurrentProcessingFactor() != AuthType.OTT ||
                ctx.getCurrentState() != MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION) {
            log.warn("Invalid context for OTT request UI. State: {}, Factor: {}",
                    ctx.getCurrentState(), ctx.getCurrentProcessingFactor());
            response.sendRedirect(request.getContextPath() + urlMatcher.getMfaInitiateUrl() +
                    "?error=invalid_ott_request_ui_context");
            return;
        }

        prepareOttContext(ctx, flowConfig);
        contextPersistence.saveContext(ctx, request);

        log.info("Rendering OTT request UI for session: {}", ctx.getMfaSessionId());
        chain.doFilter(request, response);
    }

    private void handleFactorChallengeInputUiPageRequest(HttpServletRequest request, HttpServletResponse response,
                                                         FilterChain chain, FactorContext ctx, AuthType requestedFactor,
                                                         AuthenticationFlowConfig flowConfig)
            throws IOException, ServletException {
        if (!isValidChallengeState(ctx, requestedFactor)) {
            log.warn("Invalid context for {} challenge UI. State: {}, Factor: {}",
                    requestedFactor, ctx.getCurrentState(), ctx.getCurrentProcessingFactor());
            response.sendRedirect(request.getContextPath() + urlMatcher.getMfaInitiateUrl() +
                    "?error=invalid_challenge_input_page_context");
            return;
        }

        prepareFactorContext(ctx, requestedFactor, flowConfig);
        ctx.changeState(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
        contextPersistence.saveContext(ctx, request);

        log.info("Rendering {} challenge UI for session: {}", requestedFactor, ctx.getMfaSessionId());
        chain.doFilter(request, response);
    }

    private void handleTokenGenerationRequest(HttpServletRequest request, HttpServletResponse response,
                                              FilterChain chain, FactorContext ctx,
                                              AuthenticationFlowConfig flowConfig)
            throws IOException, ServletException {
        if (!isValidTokenGenerationContext(ctx, request, flowConfig)) {
            responseWriter.writeErrorResponse(response, HttpStatus.BAD_REQUEST.value(),
                    "INVALID_TOKEN_GENERATION", "Invalid request for token generation", "");
            return;
        }

        ctx.changeState(MfaState.FACTOR_CHALLENGE_SENT_AWAITING_UI);
        contextPersistence.saveContext(ctx, request);

        log.info("Processing token generation for OTT (StepId: {})", ctx.getCurrentStepId());
        chain.doFilter(request, response);
    }

    private void handleLoginProcessingRequest(HttpServletRequest request, HttpServletResponse response,
                                              FilterChain chain, FactorContext ctx,
                                              AuthenticationFlowConfig flowConfig)
            throws IOException, ServletException {
        if (!isValidLoginProcessingContext(ctx, request, flowConfig)) {
            responseWriter.writeErrorResponse(response, HttpStatus.BAD_REQUEST.value(),
                    "INVALID_LOGIN_PROCESSING", "Invalid request for factor processing", "");
            return;
        }

        contextPersistence.saveContext(ctx, request);

        log.info("Processing {} factor verification for session: {}",
                ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());
        chain.doFilter(request, response);
    }

    // 유효성 검증 메서드들
    private boolean isValidChallengeState(FactorContext ctx, AuthType requestedFactor) {
        return ctx.getCurrentProcessingFactor() == requestedFactor &&
                (ctx.getCurrentState() == MfaState.FACTOR_CHALLENGE_SENT_AWAITING_UI ||
                        ctx.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION ||
                        ctx.getCurrentState() == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
    }

    private boolean isValidTokenGenerationContext(FactorContext ctx, HttpServletRequest request,
                                                  AuthenticationFlowConfig flowConfig) {
        if (ctx.getCurrentProcessingFactor() != AuthType.OTT || !StringUtils.hasText(ctx.getCurrentStepId())) {
            return false;
        }

        Optional<OttOptions> ottOptions = getFactorOptionsByStepId(flowConfig, ctx.getCurrentStepId(),
                AuthType.OTT, OttOptions.class);
        return ottOptions.isPresent() && request.getRequestURI().equals(ottOptions.get().getTokenGeneratingUrl());
    }

    private boolean isValidLoginProcessingContext(FactorContext ctx, HttpServletRequest request,
                                                  AuthenticationFlowConfig flowConfig) {
        AuthType currentFactor = ctx.getCurrentProcessingFactor();
        if ((currentFactor != AuthType.OTT && currentFactor != AuthType.PASSKEY) ||
                !StringUtils.hasText(ctx.getCurrentStepId())) {
            return false;
        }

        if (ctx.getCurrentState() != MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION) {
            return false;
        }

        if (currentFactor == AuthType.OTT) {
            Optional<OttOptions> ottOptions = getFactorOptionsByStepId(flowConfig, ctx.getCurrentStepId(),
                    AuthType.OTT, OttOptions.class);
            return ottOptions.isPresent() && request.getRequestURI().equals(ottOptions.get().getLoginProcessingUrl());
        }

        return true;
    }

    // 컨텍스트 준비 메서드들
    private void prepareOttContext(FactorContext ctx, AuthenticationFlowConfig flowConfig) {
        if (!StringUtils.hasText(ctx.getCurrentStepId()) || ctx.getCurrentFactorOptions() == null) {
            Optional<AuthenticationStepConfig> ottStep = findStepConfigByFactorType(flowConfig, AuthType.OTT,
                    ctx.getLastCompletedFactorOrder());
            ottStep.ifPresent(step -> {
                ctx.setCurrentStepId(step.getStepId());
                setFactorOptionsByStepIdInContext(ctx, AuthType.OTT, step.getStepId(), flowConfig);
            });
        }
    }

    private void prepareFactorContext(FactorContext ctx, AuthType factorType, AuthenticationFlowConfig flowConfig) {
        if (!StringUtils.hasText(ctx.getCurrentStepId()) || ctx.getCurrentFactorOptions() == null) {
            Optional<AuthenticationStepConfig> step = findStepConfigByFactorType(flowConfig, factorType,
                    ctx.getLastCompletedFactorOrder());
            step.ifPresent(s -> {
                ctx.setCurrentStepId(s.getStepId());
                setFactorOptionsByStepIdInContext(ctx, factorType, s.getStepId(), flowConfig);
            });
        }
    }

    // Helper 메서드들
    private Optional<AuthenticationStepConfig> findStepConfigByFactorType(AuthenticationFlowConfig flowConfig,
                                                                          AuthType factorType, int minOrder) {
        if (flowConfig == null || flowConfig.getStepConfigs() == null) {
            return Optional.empty();
        }

        return flowConfig.getStepConfigs().stream()
                .filter(step -> step.getOrder() > minOrder &&
                        factorType.name().equalsIgnoreCase(step.getType()))
                .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder));
    }

    private <T extends AuthenticationProcessingOptions> Optional<T> getFactorOptionsByStepId(
            AuthenticationFlowConfig flowConfig, String stepId, AuthType factorType, Class<T> optionClass) {
        if (flowConfig == null || !StringUtils.hasText(stepId) || flowConfig.getStepConfigs() == null) {
            return Optional.empty();
        }

        return flowConfig.getStepConfigs().stream()
                .filter(step -> stepId.equals(step.getStepId()) &&
                        factorType.name().equalsIgnoreCase(step.getType()))
                .findFirst()
                .flatMap(step -> extractOptionsFromStep(step, optionClass));
    }

    private <T extends AuthenticationProcessingOptions> Optional<T> extractOptionsFromStep(
            AuthenticationStepConfig step, Class<T> optionClass) {
        Object optionsObj = step.getOptions().get(optionClass.getName());
        if (optionClass.isInstance(optionsObj)) {
            return Optional.of(optionClass.cast(optionsObj));
        }

        Object genericOptions = step.getOptions().get("_options");
        if (optionClass.isInstance(genericOptions)) {
            return Optional.of(optionClass.cast(genericOptions));
        }

        return Optional.empty();
    }

    private void setFactorOptionsByStepIdInContext(FactorContext ctx, AuthType factorType, String stepId,
                                                   AuthenticationFlowConfig flowConfig) {
        if (factorType == AuthType.OTT) {
            getFactorOptionsByStepId(flowConfig, stepId, AuthType.OTT, OttOptions.class)
                    .ifPresent(ctx::setCurrentFactorOptions);
        } else if (factorType == AuthType.PASSKEY) {
            getFactorOptionsByStepId(flowConfig, stepId, AuthType.PASSKEY, PasskeyOptions.class)
                    .ifPresent(ctx::setCurrentFactorOptions);
        }
    }

    // 에러 처리 메서드들
    public void handleInvalidContext(HttpServletRequest request, HttpServletResponse response) throws IOException {
        log.warn("Invalid MFA context for request: {}", request.getRequestURI());
        contextPersistence.deleteContext(request);

        String targetUrl = UriComponentsBuilder.fromPath(request.getContextPath() + "/loginForm")
                .queryParam("mfa_error", "MFA_SESSION_INVALID")
                .queryParam("message", URLEncoder.encode("MFA 세션이 유효하지 않습니다.", StandardCharsets.UTF_8))
                .build().toUriString();

        response.sendRedirect(targetUrl);
    }

    public void handleTerminalContext(HttpServletRequest request, HttpServletResponse response,
                                      FactorContext ctx) throws IOException {
        log.info("MFA session {} is in terminal state: {}. Clearing context.",
                ctx.getMfaSessionId(), ctx.getCurrentState());
        contextPersistence.deleteContext(request);
        response.sendRedirect(request.getContextPath() + "/loginForm?mfa_error=mfa_session_already_ended");
    }

    public void handleConfigError(HttpServletRequest request, HttpServletResponse response,
                                  FactorContext ctx, String message) throws IOException {
        log.error("Configuration error for flow '{}': {}", ctx.getFlowTypeName(), message);
        contextPersistence.deleteContext(request);

        String targetUrl = UriComponentsBuilder.fromPath(request.getContextPath() + "/loginForm")
                .queryParam("mfa_error", "MFA_CONFIG_ERROR")
                .queryParam("message", URLEncoder.encode(message, StandardCharsets.UTF_8))
                .build().toUriString();

        response.sendRedirect(targetUrl);
    }

    public void handleGenericError(HttpServletRequest request, HttpServletResponse response,
                                   FactorContext ctx, Exception e) throws IOException {
        log.error("Error during MFA processing for session {}: {}",
                ctx != null ? ctx.getMfaSessionId() : "N/A", e.getMessage(), e);

        if (ctx != null) {
            contextPersistence.deleteContext(request);
        }

        if (!response.isCommitted()) {
            String mfaFailurePage = request.getContextPath() + authContextProperties.getMfa().getFailureUrl();
            response.sendRedirect(mfaFailurePage + "?error=mfa_filter_exception");
        }
    }
}