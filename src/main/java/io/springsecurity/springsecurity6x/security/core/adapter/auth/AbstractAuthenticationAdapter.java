package io.springsecurity.springsecurity6x.security.core.adapter.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.core.adapter.AuthenticationAdapter;
import io.springsecurity.springsecurity6x.security.handler.MfaFactorProcessingSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.UnifiedAuthenticationFailureHandler;
import io.springsecurity.springsecurity6x.security.handler.PrimaryAuthenticationSuccessHandler;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Slf4j
public abstract class AbstractAuthenticationAdapter<O extends AuthenticationProcessingOptions> implements AuthenticationAdapter {

    protected abstract void configureHttpSecurity(HttpSecurity http, O options,
                                                  AuthenticationSuccessHandler successHandler,
                                                  AuthenticationFailureHandler failureHandler) throws Exception;

    protected void configureHttpSecurityForOtt(HttpSecurity http, OttOptions options,
                                               OneTimeTokenGenerationSuccessHandler ottSuccessHandler,
                                               AuthenticationSuccessHandler successHandler,
                                               AuthenticationFailureHandler failureHandler) throws Exception {
        if (!(this instanceof OttAuthenticationAdapter)) {
            throw new UnsupportedOperationException(
                    String.format("Feature %s is not an OTT feature and should not call configureHttpSecurityForOtt. " +
                            "This method must be overridden by OttAuthenticationAdapter.", getId())
            );
        }
    }

    @Override
    public void apply(HttpSecurity http, List<AuthenticationStepConfig> allStepsInCurrentFlow, StateConfig stateConfig) throws Exception {
        Objects.requireNonNull(http, "HttpSecurity cannot be null");

        AuthenticationStepConfig myRelevantStepConfig = null;
        if (!CollectionUtils.isEmpty(allStepsInCurrentFlow)) {
            for (AuthenticationStepConfig step : allStepsInCurrentFlow) {
                if (getId().equalsIgnoreCase(step.getType())) {
                    myRelevantStepConfig = step;
                    break;
                }
            }
        }

        if (myRelevantStepConfig == null) {
            log.trace("AuthenticationFeature [{}]: No relevant AuthenticationStepConfig found in the current flow's steps. Skipping specific configuration for this HttpSecurity instance.", getId());
            return;
        }

        AuthenticationFlowConfig currentFlow = http.getSharedObject(AuthenticationFlowConfig.class);
        log.debug("AuthenticationFeature [{}]: Applying for its relevant step: {} in flow: {}",
                getId(), myRelevantStepConfig.getType(), (currentFlow != null ? currentFlow.getTypeName() : "Single/Unknown"));

        @SuppressWarnings("unchecked")
        O options = (O) myRelevantStepConfig.getOptions().get("_options");
        if (options == null) {
            throw new IllegalStateException(
                    String.format("AuthenticationFeature [%s]: Options not found in AuthenticationStepConfig for type '%s'. " +
                            "Ensure XxxDslConfigurerImpl correctly builds and stores options.", getId(), myRelevantStepConfig.getType())
            );
        }

        PlatformContext platformContext = http.getSharedObject(PlatformContext.class);
        Assert.state(platformContext != null, "PlatformContext not found in HttpSecurity shared objects. It must be set by the orchestrator.");
        ApplicationContext appContext = platformContext.applicationContext();
        Objects.requireNonNull(appContext, "ApplicationContext from PlatformContext cannot be null");

        AuthenticationSuccessHandler successHandler = resolveSuccessHandler(options, currentFlow, myRelevantStepConfig, allStepsInCurrentFlow, appContext);
        AuthenticationFailureHandler failureHandler = resolveFailureHandler(options, currentFlow, myRelevantStepConfig, allStepsInCurrentFlow, appContext);
        OneTimeTokenGenerationSuccessHandler generationSuccessHandler; // 변수 선언만

        if (this instanceof OttAuthenticationAdapter ottAdapter) {
                generationSuccessHandler = determineDefaultOttGenerationSuccessHandler(options, currentFlow, myRelevantStepConfig, allStepsInCurrentFlow, appContext);
                log.debug("AuthenticationFeature [{}]: Using provided successHandler as OneTimeTokenGenerationSuccessHandler: {}",
                        getId(), successHandler.getClass().getName());

                if (generationSuccessHandler == null) {
                    // determineDefaultOttSuccessHandler가 null을 반환하지 않도록 보장하는 것이 중요.
                    // 만약 null을 반환할 수 있다면, 여기서 적절한 기본값을 설정하거나 예외를 던져야 함.
                    // (이전 답변에서 determineDefaultOttSuccessHandler가 null이 아닌 값을 반환하도록 수정했음)
                    log.error("AuthenticationFeature [{}]: CRITICAL - determineDefaultOttSuccessHandler returned null. This should not happen. Review OttAuthenticationAdapter.determineDefaultOttSuccessHandler.", getId());
                    throw new IllegalStateException("Unable to determine a valid OneTimeTokenGenerationSuccessHandler for OTT feature " + getId() +
                            ". Resolved successHandler was: " + successHandler.getClass().getName() +
                            " and determineDefaultOttSuccessHandler also returned null.");
                }
            // 이 시점에서 resolvedOttSuccessHandler는 null이 아님을 보장.
            ottAdapter.configureHttpSecurityForOtt(http, (OttOptions)options, generationSuccessHandler, successHandler, failureHandler);
        } else {
            configureHttpSecurity(http, options, successHandler, failureHandler);
        }

        // 공통 보안 설정을 옵션 객체를 통해 HttpSecurity에 적용
        // (AbstractOptions.applyCommonSecurityConfigs(HttpSecurity) 메서드가 호출됨)
        if (options != null && http != null) {
            options.applyCommonSecurityConfigs(http);
        }

        log.info("AuthenticationFeature [{}]: Applied its specific configuration for step type '{}' in flow '{}'.",
                getId(), myRelevantStepConfig.getType(), (currentFlow != null ? currentFlow.getTypeName() : "Single/Unknown"));
    }

    protected AuthenticationSuccessHandler resolveSuccessHandler(
            O options, @Nullable AuthenticationFlowConfig currentFlow,
            AuthenticationStepConfig myStepConfig, @Nullable List<AuthenticationStepConfig> allSteps,
            ApplicationContext appContext) {
        if (options.getSuccessHandler() != null) {
            log.debug("AuthenticationFeature [{}]: Using successHandler from options: {}", getId(), options.getSuccessHandler().getClass().getSimpleName());
            return options.getSuccessHandler();
        }
/*
        if (currentFlow != null && "mfa".equalsIgnoreCase(currentFlow.getTypeName()) && allSteps != null) {
            int currentStepIndex = allSteps.indexOf(myStepConfig);
            boolean isFirstStepInMfaFlow = (currentStepIndex == 0);
            boolean isLastStepInMfaFlow = (currentStepIndex == allSteps.size() - 1);

            if (isFirstStepInMfaFlow) {
                log.debug("AuthenticationFeature [{}]: Resolving successHandler for MFA primary step.", getId());
                return appContext.getBean(UnifiedAuthenticationSuccessHandler.class);
            } else if (isLastStepInMfaFlow) {
                log.debug("AuthenticationFeature [{}]: Resolving successHandler for MFA final factor step.", getId());
                return Optional.ofNullable(currentFlow.getFinalSuccessHandler())
                        .orElseGet(() -> appContext.getBean(UnifiedAuthenticationSuccessHandler.class));
            } else {
                log.debug("AuthenticationFeature [{}]: Resolving successHandler for MFA intermediate factor step.", getId());
                return appContext.getBean(MfaFactorProcessingSuccessHandler.class);
            }
        }
        log.debug("AuthenticationFeature [{}]: Resolving default successHandler.", getId());
        return determineDefaultSuccessHandler(options, currentFlow, myStepConfig, allSteps, appContext);*/

        if (currentFlow != null && "mfa".equalsIgnoreCase(currentFlow.getTypeName()) && allSteps != null) {
            int currentStepIndex = allSteps.indexOf(myStepConfig);
            boolean isFirstStepInMfaFlow = (currentStepIndex == 0);

            if (isFirstStepInMfaFlow) {
                log.debug("AuthenticationFeature [{}]: Resolving successHandler for MFA primary step.", getId());
                return appContext.getBean(PrimaryAuthenticationSuccessHandler.class);
            } else {
                log.debug("AuthenticationFeature [{}]: Resolving successHandler for MFA intermediate factor step.", getId());
                return appContext.getBean(MfaFactorProcessingSuccessHandler.class);
            }
        }
        log.debug("AuthenticationFeature [{}]: Resolving default successHandler.", getId());
        return determineDefaultSuccessHandler(options, currentFlow, myStepConfig, allSteps, appContext);
    }

    protected AuthenticationFailureHandler resolveFailureHandler(
            O options, @Nullable AuthenticationFlowConfig currentFlow,
            AuthenticationStepConfig myStepConfig, @Nullable List<AuthenticationStepConfig> allSteps,
            ApplicationContext appContext) {
        if (options.getFailureHandler() != null) {
            log.debug("AuthenticationFeature [{}]: Using failureHandler from options: {}", getId(), options.getFailureHandler().getClass().getSimpleName());
            return options.getFailureHandler();
        }

        if (currentFlow != null && "mfa".equalsIgnoreCase(currentFlow.getTypeName())) {
            Object mfaSpecificFailureHandler = currentFlow.getMfaFailureHandler();
            if (mfaSpecificFailureHandler instanceof AuthenticationFailureHandler springSecurityFailureHandler) {
                log.debug("AuthenticationFeature [{}]: Using MfaFailureHandler from current MFA flow config.", getId());
                return springSecurityFailureHandler;
            } else if (mfaSpecificFailureHandler != null) {
                log.warn("AuthenticationFeature [{}]: MfaFailureHandler in MFA flow config is not an instance of Spring Security AuthenticationFailureHandler. Type: {}. Using platform default.",
                        getId(), mfaSpecificFailureHandler.getClass().getName());
                return appContext.getBean(UnifiedAuthenticationFailureHandler.class);
            } else {
                log.debug("AuthenticationFeature [{}]: No MfaFailureHandler set in MFA flow config. Using platform default MfaAuthenticationFailureHandler.", getId());
                return appContext.getBean(UnifiedAuthenticationFailureHandler.class);
            }
        }
        log.debug("AuthenticationFeature [{}]: Resolving default failureHandler.", getId());
        return createDefaultFailureHandler(options, appContext);
    }

    protected AuthenticationSuccessHandler determineDefaultSuccessHandler(
            O options, @Nullable AuthenticationFlowConfig currentFlow,
            AuthenticationStepConfig myStepConfig, @Nullable List<AuthenticationStepConfig> allSteps,
            ApplicationContext appContext) {
        try {
            return appContext.getBean("unifiedAuthenticationFailureHandler", AuthenticationSuccessHandler.class);
        } catch (Exception e) {
            log.warn("AuthenticationFeature [{}]: Default success handler bean 'jwtEmittingAndMfaAwareSuccessHandler' not found. Defaulting to simple redirect to '/'.", getId(), e);
            return (request, response, authentication) -> {
                if (!response.isCommitted()) response.sendRedirect("/");
            };
        }
    }

    /**
     * OTT 기능에 대한 기본 {@link OneTimeTokenGenerationSuccessHandler}를 결정합니다.
     * 이 메서드는 {@link OttAuthenticationAdapter}에서 반드시 재정의되어야 하며,
     * null을 반환해서는 안 됩니다.
     */
    protected OneTimeTokenGenerationSuccessHandler determineDefaultOttGenerationSuccessHandler(
            O options, @Nullable AuthenticationFlowConfig currentFlow,
            AuthenticationStepConfig myStepConfig, @Nullable List<AuthenticationStepConfig> allSteps,
            ApplicationContext appContext) {
        log.debug("AuthenticationFeature [{}]: Determining default OTT success handler. This should be overridden in OttAuthenticationAdapter.", getId());
        try {
            // CustomTokenIssuingSuccessHandler가 OneTimeTokenGenerationSuccessHandler를 구현하고 있다면,
            // 또는 플랫폼에 정의된 다른 기본 OTT 성공 핸들러 빈 이름을 사용합니다.
            // 예시: return appContext.getBean(MagicLinkHandler.class); // 만약 MagicLinkHandler가 있다면
            return appContext.getBean("oneTimeTokenCreationSuccessHandler", OneTimeTokenGenerationSuccessHandler.class);
        } catch (Exception e) {
            String errorMessage = String.format("Default OneTimeTokenGenerationSuccessHandler bean ('oneTimeTokenCreationSuccessHandler' or specific OTT handler) not found for OTT feature: %s. This is a critical configuration error.", getId());
            log.error(errorMessage, e);
            throw new IllegalStateException(errorMessage, e);
        }
    }

    protected AuthenticationFailureHandler createDefaultFailureHandler(O options, ApplicationContext appContext) {
        if (options instanceof RestOptions) {
            final ObjectMapper objectMapper;
            try {
                objectMapper = appContext.getBean(ObjectMapper.class);
            } catch (Exception e) {
                log.error("AuthenticationFeature [{}]: ObjectMapper bean not found for creating default REST failure handler. Cannot provide JSON error response.", getId(), e);
                return (request, response, exception) -> {
                    if (!response.isCommitted()) response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication Failed: ObjectMapper not available");
                };
            }
            return (request, response, exception) -> {
                if (!response.isCommitted()) {
                    log.warn("AuthenticationFeature [{}]: Default REST authentication failure: {}", getId(), exception.getMessage());
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    try {
                        objectMapper.writeValue(response.getWriter(),
                                Map.of("timestamp", System.currentTimeMillis(),
                                        "status", HttpServletResponse.SC_UNAUTHORIZED,
                                        "error", "Unauthorized",
                                        "message", exception.getMessage() != null ? exception.getMessage() : "Invalid credentials.",
                                        "path", request.getRequestURI()));
                    } catch (IOException ioException) {
                        log.error("AuthenticationFeature [{}]: Error writing JSON error response.", getId(), ioException);
                    }
                }
            };
        } else {
            String failureUrl = determineDefaultFailureUrl(options);
            log.debug("AuthenticationFeature [{}]: Using default failure URL: {} for non-REST flow.", getId(), failureUrl);
            return new SimpleUrlAuthenticationFailureHandler(failureUrl);
        }
    }

    protected String determineDefaultFailureUrl(O options) {
        return "/login?error&feature_type=" + getId();
    }
}
