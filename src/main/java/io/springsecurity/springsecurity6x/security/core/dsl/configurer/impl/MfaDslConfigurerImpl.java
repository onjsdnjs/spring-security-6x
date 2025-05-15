package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.FormDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.MfaDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.PrimaryAuthDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RestDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factor.ott.OttFactorDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factor.passkey.PasskeyFactorDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factory.FactorDslConfigurerFactory;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.AdaptiveConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.*;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaContinuationHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.options.OttFactorOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.options.PasskeyFactorOptions;
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

    // MFA 단계를 순서대로 저장할 리스트
    private final List<AuthenticationStepConfig> configuredSteps = new ArrayList<>();
    private int currentStepOrder = 0; // 내부적으로 스텝 순서 관리를 위함 (선택적)

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
        // Primary Authentication도 하나의 스텝으로 볼 수 있다면 configuredSteps에 추가 가능
        // 또는 primaryAuthenticationOptions는 별도로 관리
        return this;
    }

    @Override
    public MfaDslConfigurer form(Customizer<FormDslConfigurer> formConfigurerCustomizer) {
        FormDslOptionsBuilderConfigurer configurer = new FormDslOptionsBuilderConfigurer();
        formConfigurerCustomizer.customize(configurer);
        FormOptions formOptions = configurer.buildConcreteOptions();

        // PrimaryAuthenticationOptions 구성
        this.primaryAuthenticationOptions = PrimaryAuthenticationOptions.builder()
                .formOptions(formOptions)
                .loginProcessingUrl(formOptions.getLoginProcessingUrl())
                .build();

        // MFA 흐름의 첫 번째 스텝으로 Primary Auth Options을 AuthenticationStepConfig로 변환하여 추가
        // (또는 primaryAuthenticationOptions는 Builder에 별도 필드로 전달하고 Factor 들만 stepConfigs에 추가)
        // 여기서는 primaryAuthenticationOptions를 builder에 직접 설정하고,
        // Factor들(ott, passkey 등)을 stepConfigs에 추가하는 방식을 따름.
        // 만약 Primary Auth 자체도 하나의 'step' 으로 간주한다면 아래와 같이 추가:
        /*
        AuthenticationStepConfig primaryAuthStep = new AuthenticationStepConfig();
        primaryAuthStep.setType(AuthType.REST.name().toLowerCase()); // 또는 "primary_rest" 등 구분되는 타입
        primaryAuthStep.getOptions().put("_options", restOptions);
        primaryAuthStep.setOrder(currentStepOrder++); // 순서 부여
        this.configuredSteps.add(primaryAuthStep);
        */
        return this;
    }

    // REST 1차 인증 스텝 정의
    @Override
    public MfaDslConfigurer rest(Customizer<RestDslConfigurer> restConfigurerCustomizer) {
        RestDslOptionsBuilderConfigurer configurer = new RestDslOptionsBuilderConfigurer();
        restConfigurerCustomizer.customize(configurer);
        RestOptions restOptions = configurer.buildConcreteOptions();

        // PrimaryAuthenticationOptions 구성
        this.primaryAuthenticationOptions = PrimaryAuthenticationOptions.builder()
                .restOptions(restOptions)
                .loginProcessingUrl(restOptions.getLoginProcessingUrl())
                .build();

        // MFA 흐름의 첫 번째 스텝으로 Primary Auth Options을 AuthenticationStepConfig로 변환하여 추가
        // (또는 primaryAuthenticationOptions는 Builder에 별도 필드로 전달하고 Factor 들만 stepConfigs에 추가)
        // 여기서는 primaryAuthenticationOptions를 builder에 직접 설정하고,
        // Factor들(ott, passkey 등)을 stepConfigs에 추가하는 방식을 따름.
        // 만약 Primary Auth 자체도 하나의 'step' 으로 간주한다면 아래와 같이 추가:
        /*
        AuthenticationStepConfig primaryAuthStep = new AuthenticationStepConfig();
        primaryAuthStep.setType(AuthType.REST.name().toLowerCase()); // 또는 "primary_rest" 등 구분되는 타입
        primaryAuthStep.getOptions().put("_options", restOptions);
        primaryAuthStep.setOrder(currentStepOrder++); // 순서 부여
        this.configuredSteps.add(primaryAuthStep);
        */
        return this;
    }

    // OTT 2차 인증 스텝 정의
    @Override
    public MfaDslConfigurer ott(Customizer<OttFactorDslConfigurer> ottConfigurerCustomizer) {
        OttFactorDslConfigurer configurer = factorDslConfigurerFactory.createConfigurer(AuthType.OTT);
        ottConfigurerCustomizer.customize(configurer);
        OttFactorOptions ottOptions = configurer.buildConcreteOptions();
        this.registeredFactorOptionsMap.put(AuthType.OTT, ottOptions);

        // AuthenticationStepConfig 생성 및 configuredSteps에 추가
        AuthenticationStepConfig ottStep = new AuthenticationStepConfig();
        ottStep.setType(AuthType.OTT.name().toLowerCase());
        ottStep.getOptions().put("_options", ottOptions);
        ottStep.setOrder(currentStepOrder++); // 사용자가 지정한 order 사용 또는 순차적 증가
        this.configuredSteps.add(ottStep);
        return this;
    }

    // Passkey 2차 인증 스텝 정의
    @Override
    public MfaDslConfigurer passkey(Customizer<PasskeyFactorDslConfigurer> passkeyConfigurerCustomizer) {
        PasskeyFactorDslConfigurer configurer = factorDslConfigurerFactory.createConfigurer(AuthType.PASSKEY);
        passkeyConfigurerCustomizer.customize(configurer);
        PasskeyFactorOptions passkeyOptions = configurer.buildConcreteOptions();
        this.registeredFactorOptionsMap.put(AuthType.PASSKEY, passkeyOptions);

        // AuthenticationStepConfig 생성 및 configuredSteps에 추가
        AuthenticationStepConfig passkeyStep = new AuthenticationStepConfig();
        passkeyStep.setType(AuthType.PASSKEY.name().toLowerCase());
        passkeyStep.getOptions().put("_options", passkeyOptions);
        passkeyStep.setOrder(currentStepOrder++);
        this.configuredSteps.add(passkeyStep);
        return this;
    }

    @Override
    public MfaDslConfigurer recoveryFlow(Customizer<RecoveryDslConfigurer> recoveryConfigurerCustomizer) {
        RecoveryDslConfigurer configurer = factorDslConfigurerFactory.createConfigurer(AuthType.RECOVERY_CODE);
        recoveryConfigurerCustomizer.customize(configurer);
        FactorAuthenticationOptions recoveryOptions = configurer.buildConcreteOptions();
        this.registeredFactorOptionsMap.put(AuthType.RECOVERY_CODE, recoveryOptions);

        // 복구 흐름도 하나의 스텝으로 추가 가능
        AuthenticationStepConfig recoveryStep = new AuthenticationStepConfig();
        recoveryStep.setType(AuthType.RECOVERY_CODE.name().toLowerCase());
        recoveryStep.getOptions().put("_options", recoveryOptions);
        recoveryStep.setOrder(currentStepOrder++);
        this.configuredSteps.add(recoveryStep);
        return this;
    }


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
        Assert.notNull(primaryAuthenticationOptions, "Primary authentication (e.g., using .rest() or .form() in primaryAuthentication()) must be configured for MFA flow.");
        // configuredSteps 리스트에 Primary Auth 스텝이 포함되지 않았다면, 여기서 추가하거나
        // AuthenticationFlowConfig.Builder에서 Primary Auth와 Factor Steps를 별도로 받아 처리하도록 변경 필요.
        // 현재는 Factor들만 configuredSteps에 추가되도록 로직을 수정했으므로,
        // Builder의 primaryAuthenticationOptions()를 통해 1차 인증 설정을 전달하고,
        // stepConfigs()를 통해 2차 이후 Factor 스텝들을 전달합니다.

        // configuredSteps가 비어있으면 안됨 (최소 하나 이상의 Factor가 있어야 MFA 의미가 있음)
        Assert.isTrue(!configuredSteps.isEmpty(), "MFA flow must have at least one factor (e.g., ott, passkey) configured.");

        flowConfigBuilder
                .typeName(AuthType.MFA.name().toLowerCase())
                .order(this.order)
                .primaryAuthenticationOptions(this.primaryAuthenticationOptions) // 1차 인증 옵션 설정
                .stepConfigs(this.configuredSteps) // 2차 이후 인증 스텝(Factor)들 설정
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


