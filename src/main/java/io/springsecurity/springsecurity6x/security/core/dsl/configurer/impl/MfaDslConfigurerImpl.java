package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.*;
import io.springsecurity.springsecurity6x.security.core.dsl.factory.AuthMethodConfigurerFactory;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.AdaptiveConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.AdaptiveDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.RetryPolicyDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.RetryPolicyDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaContinuationHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.exception.DslConfigurationException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

import java.util.*;

public class MfaDslConfigurerImpl implements MfaDslConfigurer {

    private final AuthenticationFlowConfig.Builder flowConfigBuilder;
    private final AuthMethodConfigurerFactory authMethodConfigurerFactory;

    private MfaPolicyProvider policyProvider;
    private MfaContinuationHandler continuationHandler;
    private MfaFailureHandler mfaFailureHandler;
    private AuthenticationSuccessHandler finalSuccessHandler;
    private RetryPolicy defaultRetryPolicy;
    private AdaptiveConfig defaultAdaptiveConfig;
    private boolean defaultDeviceTrustEnabled = false;
    private int order;

    private final List<AuthenticationStepConfig> configuredSteps = new ArrayList<>();
    private int currentStepOrderCounter = 0;

    public MfaDslConfigurerImpl(AuthenticationFlowConfig.Builder flowConfigBuilder, ApplicationContext applicationContext) {
        this.flowConfigBuilder = flowConfigBuilder;
        this.authMethodConfigurerFactory = new AuthMethodConfigurerFactory(applicationContext);
    }

    @Override
    public MfaDslConfigurer order(int order) {
        this.order = order;
        return this;
    }

    private int assignOrderAndIncrement() {
        return currentStepOrderCounter++;
    }

    private void addPrimaryAuthStep(AuthType authType, AuthenticationProcessingOptions options) {
        if (configuredSteps.stream().anyMatch(s -> s.getOrder() == 0)) {
            throw new IllegalStateException("Primary authentication (form/rest) has already been configured for this MFA flow.");
        }
        AuthenticationStepConfig primaryAuthStep = new AuthenticationStepConfig();
        primaryAuthStep.setType(authType.name().toLowerCase());
        primaryAuthStep.getOptions().put("_options", options);
        primaryAuthStep.setOrder(assignOrderAndIncrement());
        configuredSteps.add(primaryAuthStep);
    }

    @Override
    public MfaDslConfigurer form(Customizer<FormDslConfigurer> formConfigurerCustomizer) {
        FormDslConfigurer configurer = authMethodConfigurerFactory.createConfigurer(AuthType.FORM);
        formConfigurerCustomizer.customize(configurer);
        addPrimaryAuthStep(AuthType.FORM, configurer.buildConcreteOptions());
        return this;
    }

    @Override
    public MfaDslConfigurer rest(Customizer<RestDslConfigurer> restConfigurerCustomizer) {
        RestDslConfigurer configurer = authMethodConfigurerFactory.createConfigurer(AuthType.REST);
        restConfigurerCustomizer.customize(configurer);
        addPrimaryAuthStep(AuthType.REST, configurer.buildConcreteOptions());
        return this;
    }


    private <O extends AuthenticationProcessingOptions, C extends AuthenticationFactorConfigurer<O, C>>
    MfaDslConfigurer configureMfaFactor(
            AuthType authType,
            Customizer<C> factorConfigurerCustomizer) {

        C configurer = authMethodConfigurerFactory.createConfigurer(authType);
        factorConfigurerCustomizer.customize(configurer);
        O factorOptions = configurer.buildConcreteOptions();

        AuthenticationStepConfig factorStep = new AuthenticationStepConfig();
        factorStep.setType(authType.name().toLowerCase());
        factorStep.getOptions().put("_options", factorOptions);
        factorStep.setOrder(assignOrderAndIncrement());
        this.configuredSteps.add(factorStep);
        return this;
    }

    @Override
    public MfaDslConfigurer ott(Customizer<OttDslConfigurer> ottConfigurerCustomizer) {
        return configureMfaFactor(AuthType.OTT, ottConfigurerCustomizer);
    }

    @Override
    public MfaDslConfigurer passkey(Customizer<PasskeyDslConfigurer> passkeyConfigurerCustomizer) {
        return configureMfaFactor(AuthType.PASSKEY, passkeyConfigurerCustomizer);
    }

    @Override
    public MfaDslConfigurer recoveryFlow(Customizer<RecoveryCodeDslConfigurer> recoveryConfigurerCustomizer) {
        return configureMfaFactor(AuthType.RECOVERY_CODE, recoveryConfigurerCustomizer);
    }

    @Override
    public MfaDslConfigurer mfaContinuationHandler(MfaContinuationHandler continuationHandler) {
        this.continuationHandler = continuationHandler;
        return this;
    }

    @Override
    public MfaDslConfigurer mfaFailureHandler(MfaFailureHandler failureHandler) {
        this.mfaFailureHandler = failureHandler;
        return this;
    }

    @Override
    public MfaDslConfigurer policyProvider(MfaPolicyProvider policyProvider) {
        this.policyProvider = policyProvider;
        return this;
    }

    @Override
    public MfaDslConfigurer finalSuccessHandler(AuthenticationSuccessHandler handler) {
        this.finalSuccessHandler = handler;
        return this;
    }

    @Override
    public MfaDslConfigurer defaultRetryPolicy(Customizer<RetryPolicyDslConfigurer> c) {
        RetryPolicyDslConfigurerImpl configurer = new RetryPolicyDslConfigurerImpl();
        c.customize(configurer);
        this.defaultRetryPolicy = configurer.build();
        return this;
    }

    @Override
    public MfaDslConfigurer defaultAdaptivePolicy(Customizer<io.springsecurity.springsecurity6x.security.core.mfa.configurer.AdaptiveDslConfigurer> c) {
        AdaptiveDslConfigurerImpl configurer = new AdaptiveDslConfigurerImpl();
        c.customize(configurer);
        this.defaultAdaptiveConfig = configurer.build();
        return this;
    }

    @Override
    public MfaDslConfigurer defaultDeviceTrustEnabled(boolean enable) {
        this.defaultDeviceTrustEnabled = enable;
        return this;
    }

    @Override
    public MfaDslConfigurer primaryAuthentication(Customizer<PrimaryAuthDslConfigurer> primaryAuthConfig) {
        throw new UnsupportedOperationException("primaryAuthentication() is deprecated for MFA flow. Use form() or rest() directly within the MFA block to set the primary authentication method as the first step.");
    }


    @Override
    public AuthenticationFlowConfig build() {
        Assert.isTrue(!configuredSteps.isEmpty(), "MFA flow must have at least one step.");
        configuredSteps.sort(Comparator.comparingInt(AuthenticationStepConfig::getOrder));

        AuthenticationStepConfig firstStep = configuredSteps.get(0);
        Assert.isTrue(firstStep.getOrder() == 0 &&
                        (AuthType.FORM.name().equalsIgnoreCase(firstStep.getType()) || AuthType.REST.name().equalsIgnoreCase(firstStep.getType())),
                "MFA flow must start with a FORM or REST primary authentication step (order 0).");
        Assert.isTrue(configuredSteps.size() > 1, "MFA flow must have at least one secondary authentication factor (e.g., OTT, Passkey) configured after primary authentication.");

        Object firstStepOptionsObject = firstStep.getOptions().get("_options");
        PrimaryAuthenticationOptions primaryAuthOptionsForFlow;

        if (firstStepOptionsObject instanceof FormOptions) {
            primaryAuthOptionsForFlow = PrimaryAuthenticationOptions.builder().formOptions((FormOptions) firstStepOptionsObject).build();
        } else if (firstStepOptionsObject instanceof RestOptions) {
            primaryAuthOptionsForFlow = PrimaryAuthenticationOptions.builder().restOptions((RestOptions) firstStepOptionsObject).build();
        } else {
            throw new DslConfigurationException("Primary authentication step's options are not of type FormOptions or RestOptions. Actual type: " + (firstStepOptionsObject != null ? firstStepOptionsObject.getClass().getName() : "null"));
        }

        Map<AuthType, AuthenticationProcessingOptions> factorOptionsMap = new HashMap<>();
        for (int i = 1; i < configuredSteps.size(); i++) {
            AuthenticationStepConfig step = configuredSteps.get(i);
            Object stepOptionsObject = step.getOptions().get("_options");
            if (!(stepOptionsObject instanceof AuthenticationProcessingOptions)) {
                throw new DslConfigurationException("Options for step '" + step.getType() + "' are not of type AuthenticationProcessingOptions.");
            }
            try {
                AuthType factorType = AuthType.valueOf(step.getType().toUpperCase());
                factorOptionsMap.put(factorType, (AuthenticationProcessingOptions) stepOptionsObject);
            } catch (IllegalArgumentException e) {
                throw new DslConfigurationException("Invalid AuthType string in stepConfig: " + step.getType(), e);
            }
        }

        flowConfigBuilder
                .typeName(AuthType.MFA.name().toLowerCase())
                .order(this.order)
                .primaryAuthenticationOptions(primaryAuthOptionsForFlow)
                .stepConfigs(Collections.unmodifiableList(new ArrayList<>(this.configuredSteps)))
                .mfaPolicyProvider(this.policyProvider)
                .mfaContinuationHandler(this.continuationHandler)
                .mfaFailureHandler(this.mfaFailureHandler)
                .finalSuccessHandler(this.finalSuccessHandler)
                .registeredFactorOptions(factorOptionsMap)
                .defaultRetryPolicy(this.defaultRetryPolicy)
                .defaultAdaptiveConfig(this.defaultAdaptiveConfig)
                .defaultDeviceTrustEnabled(this.defaultDeviceTrustEnabled);

        return flowConfigBuilder.build();
    }
}


