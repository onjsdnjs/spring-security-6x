package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.OptionsBuilderDsl;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.FormDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.MfaDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.PrimaryAuthDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RestDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factor.ott.OttFactorDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factor.passkey.PasskeyFactorDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factory.FactorDslConfigurerFactory;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.AdaptiveConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.*;
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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

    private final List<AuthenticationStepConfig> configuredSteps = new ArrayList<>();
    private int currentStepOrder = 0; // MFA 내부 Factor 들의 순서

    public MfaDslConfigurerImpl(AuthenticationFlowConfig.Builder flowConfigBuilder, ApplicationContext applicationContext) {
        this.flowConfigBuilder = flowConfigBuilder;
        this.factorDslConfigurerFactory = new FactorDslConfigurerFactory(applicationContext);
    }

    @Override
    public MfaDslConfigurer order(int order) {
        this.order = order;
        return this;
    }

    // --- Primary Authentication 설정 ---
    @Override
    public MfaDslConfigurer primaryAuthentication(Customizer<PrimaryAuthDslConfigurer> primaryAuthConfigCustomizer) {
        PrimaryAuthDslConfigurerImpl configurer = new PrimaryAuthDslConfigurerImpl();
        primaryAuthConfigCustomizer.customize(configurer);
        this.primaryAuthenticationOptions = configurer.buildOptions();
        return this;
    }

    @Override
    public MfaDslConfigurer form(Customizer<FormDslConfigurer> formConfigurerCustomizer) {
        FormDslOptionsBuilderConfigurer configurer = new FormDslOptionsBuilderConfigurer();
        formConfigurerCustomizer.customize(configurer);
        FormOptions formOptions = configurer.buildConcreteOptions();
        this.primaryAuthenticationOptions = PrimaryAuthenticationOptions.builder()
                .formOptions(formOptions)
                .loginProcessingUrl(formOptions.getLoginProcessingUrl())
                .build();
        return this;
    }

    @Override
    public MfaDslConfigurer rest(Customizer<RestDslConfigurer> restConfigurerCustomizer) {
        RestDslOptionsBuilderConfigurer configurer = new RestDslOptionsBuilderConfigurer();
        restConfigurerCustomizer.customize(configurer);
        RestOptions restOptions = configurer.buildConcreteOptions();
        this.primaryAuthenticationOptions = PrimaryAuthenticationOptions.builder()
                .restOptions(restOptions)
                .loginProcessingUrl(restOptions.getLoginProcessingUrl())
                .build();
        return this;
    }

    // --- MFA Factor (2차 인증 요소) 설정 ---

    /**
     * MFA Factor 설정을 위한 공통 헬퍼 메소드.
     *
     * @param authType                MFA Factor의 인증 타입 (예: AuthType.OTT)
     * @param factorConfigurerCustomizer 사용자 정의 Customizer
     * @param <F_OPTS>                FactorAuthenticationOptions의 하위 타입
     * @param <F_CONF>                FactorDslConfigurer의 하위 타입
     * @return MfaDslConfigurer (체이닝을 위해)
     */
    private <F_OPTS extends FactorAuthenticationOptions,
            F_CONF extends OptionsBuilderDsl<F_OPTS, F_CONF>> // Factor Configurer는 OptionsBuilderDsl을 구현해야 함
    MfaDslConfigurer configureMfaFactor(
            AuthType authType,
            Customizer<F_CONF> factorConfigurerCustomizer) {

        // FactorDslConfigurerFactory를 통해 특정 AuthType에 맞는 Configurer를 가져옴
        F_CONF configurer = factorDslConfigurerFactory.createConfigurer(authType);

        // 사용자 정의 Customizer 적용
        factorConfigurerCustomizer.customize(configurer);

        // Factor Options 빌드
        F_OPTS factorOptions = configurer.buildConcreteOptions();
        this.registeredFactorOptionsMap.put(authType, factorOptions);

        // AuthenticationStepConfig 생성 및 추가
        AuthenticationStepConfig factorStep = new AuthenticationStepConfig();
        factorStep.setType(authType.name().toLowerCase());
        factorStep.getOptions().put("_options", factorOptions); // 관례에 따라 "_options" 키 사용
        factorStep.setOrder(currentStepOrder++); // MFA 내부 단계 순서 자동 증가
        this.configuredSteps.add(factorStep);

        return this;
    }

    @Override
    public MfaDslConfigurer ott(Customizer<OttFactorDslConfigurer> ottConfigurerCustomizer) {
        return configureMfaFactor(AuthType.OTT, ottConfigurerCustomizer);
    }

    @Override
    public MfaDslConfigurer passkey(Customizer<PasskeyFactorDslConfigurer> passkeyConfigurerCustomizer) {
        return configureMfaFactor(AuthType.PASSKEY, passkeyConfigurerCustomizer);
    }

    @Override
    public MfaDslConfigurer recoveryFlow(Customizer<RecoveryDslConfigurer> recoveryConfigurerCustomizer) {
        // RecoveryDslConfigurer가 OptionsBuilderDsl<RecoveryCodeFactorOptions, RecoveryDslConfigurer>를 구현한다고 가정
        return configureMfaFactor(AuthType.RECOVERY_CODE, recoveryConfigurerCustomizer);
    }

    // --- 나머지 MFA 전역 설정 메소드들 ---
    @Override
    public MfaDslConfigurer mfaContinuationHandler(MfaContinuationHandler continuationHandler) {
        this.continuationHandler = continuationHandler;
        return this;
    }

    @Override
    public MfaDslConfigurer mfaFailureHandler(MfaFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
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
        Assert.isTrue(!configuredSteps.isEmpty(), "MFA flow must have at least one authentication factor (e.g., ott, passkey) configured after primary authentication.");

        flowConfigBuilder
                .typeName(AuthType.MFA.name().toLowerCase())
                .order(this.order)
                .primaryAuthenticationOptions(this.primaryAuthenticationOptions)
                .stepConfigs(this.configuredSteps) // 정제된 Factor 스텝 리스트 전달
                .mfaPolicyProvider(this.policyProvider)
                .mfaContinuationHandler(this.continuationHandler)
                .mfaFailureHandler(this.failureHandler)
                .finalSuccessHandler(this.finalSuccessHandler)
                .registeredFactorOptions(new HashMap<>(this.registeredFactorOptionsMap)) // 방어적 복사
                .defaultRetryPolicy(this.defaultRetryPolicy)
                .defaultAdaptiveConfig(this.defaultAdaptiveConfig)
                .defaultDeviceTrustEnabled(this.defaultDeviceTrustEnabled);

        return flowConfigBuilder.build();
    }
}


