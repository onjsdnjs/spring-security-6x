package io.springsecurity.springsecurity6x.security.core.adapter.auth;

import io.springsecurity.springsecurity6x.security.core.adapter.AuthenticationAdapter;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.handler.*;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
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
                                                  AuthenticationFlowConfig currentFlow,
                                                  PlatformAuthenticationSuccessHandler successHandler,
                                                  PlatformAuthenticationFailureHandler failureHandler) throws Exception;

    protected void configureHttpSecurityForOtt(HttpSecurity http, OttOptions options,
                                               OneTimeTokenGenerationSuccessHandler ottSuccessHandler,
                                               PlatformAuthenticationSuccessHandler  successHandler,
                                               PlatformAuthenticationFailureHandler failureHandler) throws Exception {
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

        AbstractMfaAuthenticationSuccessHandler mfaSuccessHandler = (AbstractMfaAuthenticationSuccessHandler)resolveSuccessHandler(options, currentFlow, myRelevantStepConfig, allStepsInCurrentFlow, appContext);
        UnifiedAuthenticationFailureHandler mfaFailureHandler = (UnifiedAuthenticationFailureHandler)resolveFailureHandler(options, currentFlow, appContext);

        if(options.getSuccessHandler() != null) mfaSuccessHandler.setDelegateHandler(options.getSuccessHandler());
        if(options.getFailureHandler() != null) mfaFailureHandler.setDelegateHandler(options.getFailureHandler());

        OneTimeTokenGenerationSuccessHandler generationSuccessHandler;

        if (this instanceof OttAuthenticationAdapter ottAdapter) {
                generationSuccessHandler = determineDefaultOttGenerationSuccessHandler(appContext);
                log.debug("AuthenticationFeature [{}]: Using provided successHandler as OneTimeTokenGenerationSuccessHandler: {}",
                        getId(), mfaSuccessHandler.getClass().getName());

                if (generationSuccessHandler == null) {
                    log.error("AuthenticationFeature [{}]: CRITICAL - determineDefaultOttSuccessHandler returned null. This should not happen. Review OttAuthenticationAdapter.determineDefaultOttSuccessHandler.", getId());
                    throw new IllegalStateException("Unable to determine a valid OneTimeTokenGenerationSuccessHandler for OTT feature " + getId() +
                            ". Resolved successHandler was: " + mfaSuccessHandler.getClass().getName() +
                            " and determineDefaultOttSuccessHandler also returned null.");
                }
            ottAdapter.configureHttpSecurityForOtt(http, (OttOptions)options, generationSuccessHandler, mfaSuccessHandler, mfaFailureHandler);
        } else {
            configureHttpSecurity(http, options, currentFlow, mfaSuccessHandler, mfaFailureHandler);
        }

        options.applyCommonSecurityConfigs(http);

        log.info("AuthenticationFeature [{}]: Applied its specific configuration for step type '{}' in flow '{}'.",
                getId(), myRelevantStepConfig.getType(), (currentFlow != null ? currentFlow.getTypeName() : "Single/Unknown"));
    }

    protected PlatformAuthenticationSuccessHandler resolveSuccessHandler(
            O options, @Nullable AuthenticationFlowConfig currentFlow,
            AuthenticationStepConfig myStepConfig, @Nullable List<AuthenticationStepConfig> allSteps,
            ApplicationContext appContext) {
        /*if (options.getSuccessHandler() != null) {
            log.debug("AuthenticationFeature [{}]: Using successHandler from options: {}", getId(), options.getSuccessHandler().getClass().getSimpleName());
            return options.getSuccessHandler();
        }
*/
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
        return appContext.getBean(PrimaryAuthenticationSuccessHandler.class);
    }

    protected PlatformAuthenticationFailureHandler  resolveFailureHandler(O options, @Nullable AuthenticationFlowConfig currentFlow, ApplicationContext appContext) {

        /*if (options.getFailureHandler() != null) {
            log.debug("AuthenticationFeature [{}]: Using failureHandler from options: {}", getId(), options.getFailureHandler().getClass().getSimpleName());
            return options.getFailureHandler();
        }*/

        if (currentFlow != null && "mfa".equalsIgnoreCase(currentFlow.getTypeName())) {
            return appContext.getBean(UnifiedAuthenticationFailureHandler.class);
            /*Object mfaSpecificFailureHandler = currentFlow.getMfaFailureHandler();
            if (mfaSpecificFailureHandler instanceof PlatformAuthenticationFailureHandler  springSecurityFailureHandler) {
                log.debug("AuthenticationFeature [{}]: Using MfaFailureHandler from current MFA flow config.", getId());
                return springSecurityFailureHandler;

            } else {
                log.debug("AuthenticationFeature [{}]: No MfaFailureHandler set in MFA flow config. Using platform default MfaAuthenticationFailureHandler.", getId());
                return appContext.getBean(UnifiedAuthenticationFailureHandler.class);
            }*/
        }

        log.debug("AuthenticationFeature [{}]: Resolving default failureHandler.", getId());
        return appContext.getBean(UnifiedAuthenticationFailureHandler.class);
    }

    /**
     * OTT 기능에 대한 기본 {@link OneTimeTokenGenerationSuccessHandler}를 결정합니다.
     * 이 메서드는 {@link OttAuthenticationAdapter}에서 반드시 재정의되어야 하며,
     * null을 반환해서는 안 됩니다.
     */
    protected OneTimeTokenGenerationSuccessHandler determineDefaultOttGenerationSuccessHandler(ApplicationContext appContext) {
        log.debug("AuthenticationFeature [{}]: Determining default OTT success handler. This should be overridden in OttAuthenticationAdapter.", getId());
        try {
            return appContext.getBean("oneTimeTokenCreationSuccessHandler", OneTimeTokenGenerationSuccessHandler.class);
        } catch (Exception e) {
            String errorMessage = String.format("Default OneTimeTokenGenerationSuccessHandler bean ('oneTimeTokenCreationSuccessHandler' or specific OTT handler) not found for OTT feature: %s. This is a critical configuration error.", getId());
            log.error(errorMessage, e);
            throw new IllegalStateException(errorMessage, e);
        }
    }
}
