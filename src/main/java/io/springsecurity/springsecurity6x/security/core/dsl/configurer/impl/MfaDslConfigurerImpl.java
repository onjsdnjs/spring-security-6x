package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.OptionsBuilderDsl;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.MfaDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.PrimaryAuthDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factory.FactorDslConfigurerFactory;
import io.springsecurity.springsecurity6x.security.core.mfa.AdaptiveConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.AdaptiveDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.AdaptiveDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.RetryPolicyDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.RetryPolicyDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaContinuationHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;


public class MfaDslConfigurerImpl implements MfaDslConfigurer {

    private final AuthenticationFlowConfig.Builder flowConfigBuilder;
    private final FactorDslConfigurerFactory factorDslConfigurerFactory;

    private PrimaryAuthenticationOptions primaryAuthenticationOptions;
    private MfaPolicyProvider policyProvider;
    private MfaContinuationHandler continuationHandler;
    private MfaFailureHandler failureHandler;
    private AuthenticationSuccessHandler finalSuccessHandler;
    private final Map<AuthType, FactorAuthenticationOptions> registeredFactorOptionsMap = new HashMap<>();
    private RetryPolicy defaultRetryPolicy;
    private AdaptiveConfig defaultAdaptiveConfig;
    private boolean defaultDeviceTrustEnabled = false;
    private int order;


    public MfaDslConfigurerImpl(AuthenticationFlowConfig.Builder flowConfigBuilder, ApplicationContext applicationContext) {
        this.flowConfigBuilder = flowConfigBuilder;
        this.factorDslConfigurerFactory = new FactorDslConfigurerFactory(applicationContext);
    }

    @Override
    public MfaDslConfigurer order(int order) {
        this.order = order;
        return this;
    }

    @Override
    public MfaDslConfigurer primaryAuthentication(Customizer<PrimaryAuthDslConfigurer> primaryAuthConfigCustomizer) {
        PrimaryAuthDslConfigurerImpl configurer = new PrimaryAuthDslConfigurerImpl();
        primaryAuthConfigCustomizer.customize(configurer);
        this.primaryAuthenticationOptions = configurer.buildOptions();
        return this;
    }

    @Override
    public MfaDslConfigurer mfaContinuationHandler(MfaContinuationHandler continuationHandler) {
        this.continuationHandler = continuationHandler; // 수정: 할당
        return this;
    }

    // 인터페이스와 일치하는 registerFactor 메소드
    @Override
    public <O extends FactorAuthenticationOptions, S extends OptionsBuilderDsl<O, S>> MfaDslConfigurer registerFactor(
            AuthType factorType, Customizer<S> factorConfigurerCustomizer) {
        Assert.notNull(factorType, "factorType cannot be null");
        Assert.notNull(factorConfigurerCustomizer, "factorConfigurerCustomizer cannot be null");

        // FactorDslConfigurerFactory의 createConfigurer가 올바른 S 타입을 반환해야 함
        S factorDslConfigurer = factorDslConfigurerFactory.createConfigurer(factorType);
        factorConfigurerCustomizer.customize(factorDslConfigurer);
        this.registeredFactorOptionsMap.put(factorType, factorDslConfigurer.buildConcreteOptions());
        return this;
    }


    @Override
    public MfaDslConfigurer mfaFailureHandler(MfaFailureHandler failureHandler) {
        this.failureHandler = failureHandler; // 수정: 할당
        return this;
    }

    @Override
    public MfaDslConfigurer policyProvider(MfaPolicyProvider policyProvider) {
        this.policyProvider = policyProvider;
        return this;
    }


    @Override
    public MfaDslConfigurer finalSuccessHandler(AuthenticationSuccessHandler handler) { // 파라미터명 일치
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
    public MfaDslConfigurer defaultAdaptivePolicy(Customizer<AdaptiveDslConfigurer> c) {
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
    public AuthenticationFlowConfig build() {
        Assert.notNull(primaryAuthenticationOptions, "Primary authentication must be configured for MFA flow.");
        Assert.notNull(policyProvider, "MfaPolicyProvider must be configured.");
        Assert.notNull(continuationHandler, "MfaContinuationHandler must be configured.");
        Assert.notNull(failureHandler, "MfaFailureHandler must be configured.");
        Assert.notNull(finalSuccessHandler, "FinalSuccessHandler must be configured.");
        Assert.isTrue(!registeredFactorOptionsMap.isEmpty(), "At least one MFA Factor must be registered.");

        // AuthenticationFlowConfig.Builder에 해당 setter 메소드들이 정의되어 있어야 함
        flowConfigBuilder
                .typeName(AuthType.MFA.name().toLowerCase())
                .order(this.order)
                .primaryAuthenticationOptions(this.primaryAuthenticationOptions)
                .mfaPolicyProvider(this.policyProvider)
                .mfaContinuationHandler(this.continuationHandler)
                .mfaFailureHandler(this.failureHandler)
                .finalSuccessHandler(this.finalSuccessHandler)
                .registeredFactorOptions(new HashMap<>(this.registeredFactorOptionsMap))
                .defaultRetryPolicy(this.defaultRetryPolicy)
                .defaultAdaptiveConfig(this.defaultAdaptiveConfig)
                .defaultDeviceTrustEnabled(this.defaultDeviceTrustEnabled);

        return flowConfigBuilder.build();
    }
}


