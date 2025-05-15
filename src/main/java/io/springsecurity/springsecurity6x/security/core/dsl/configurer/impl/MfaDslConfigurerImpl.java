package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;


import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.MfaDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.PrimaryAuthDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RestDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factor.ott.OttFactorDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factor.passkey.PasskeyFactorDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factory.FactorDslConfigurerFactory;
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

import java.util.HashMap;
import java.util.Map;


public class MfaDslConfigurerImpl implements MfaDslConfigurer {

    private final AuthenticationFlowConfig.Builder flowConfigBuilder;
    private final FactorDslConfigurerFactory factorDslConfigurerFactory;
    // PrimaryAuthDslConfigurerImpl은 ApplicationContext를 직접 받지 않도록 수정 (필요시 팩토리 통해 주입)
    // private final ApplicationContext applicationContext;

    // 1차 인증은 PrimaryAuthenticationOptions 타입으로 관리
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
        // this.applicationContext = applicationContext; // FactorDslConfigurerFactory 생성에만 사용
        this.factorDslConfigurerFactory = new FactorDslConfigurerFactory(applicationContext);
    }

    @Override
    public MfaDslConfigurer order(int order) {
        this.order = order;
        return this;
    }

    // 이 primaryAuthentication 메소드는 MfaDslConfigurer 인터페이스에 정의된 대로 유지.
    // 사장님의 DSL 예시에서는 이 메소드 대신 rest() 등을 직접 호출.
    @Override
    public MfaDslConfigurer primaryAuthentication(Customizer<PrimaryAuthDslConfigurer> primaryAuthConfigCustomizer) {
        // PrimaryAuthDslConfigurerImpl 클래스가 올바른 패키지에 정의되어 있고, 기본 생성자가 있다고 가정
        // 가정된 경로: io.springsecurity.springsecurity6x.security.core.dsl.configurer.mfa.impl.PrimaryAuthDslConfigurerImpl
        PrimaryAuthDslConfigurerImpl configurer = new PrimaryAuthDslConfigurerImpl();
        primaryAuthConfigCustomizer.customize(configurer);
        this.primaryAuthenticationOptions = configurer.buildOptions();
        return this;
    }

    // 사장님의 DSL 예시 (.mfa(m -> m.rest(r -> ...)))를 지원하기 위한 rest() 메소드
    // 여기서 r은 RestDslConfigurer 타입이어야 하고, 이는 OptionsBuilderDsl을 확장함.
    // RestDslOptionsBuilderConfigurer가 RestDslConfigurer를 구현.
    @Override
    public MfaDslConfigurer rest(Customizer<RestDslConfigurer> restConfigurerCustomizer) {
        // RestDslOptionsBuilderConfigurer 클래스가 올바른 패키지에 정의되어 있고, 기본 생성자가 있다고 가정
        // 가정된 경로: io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.RestDslOptionsBuilderConfigurer
        RestDslOptionsBuilderConfigurer configurer = new RestDslOptionsBuilderConfigurer();
        restConfigurerCustomizer.customize(configurer);
        // MFA 플로우의 1차 인증으로 사용될 Options를 저장.
        // PrimaryAuthenticationOptions는 RestOptions를 포함할 수 있는 구조여야 함.
        // 또는, primaryAuthenticationOptions 필드를 FactorAuthenticationOptions 타입으로 변경하고,
        // AuthenticationFlowConfig.Builder에 primaryAuthFactorOptions(FactorAuthenticationOptions) setter가 있어야 함.
        // 여기서는 PrimaryAuthenticationOptions.Builder에 .restOptions()가 있다고 가정.
        this.primaryAuthenticationOptions = PrimaryAuthenticationOptions.builder()
                .restOptions(configurer.buildConcreteOptions())
                .loginProcessingUrl(configurer.buildConcreteOptions().getLoginProcessingUrl()) // URL 일치
                .build();
        return this;
    }

    @Override
    public MfaDslConfigurer ott(Customizer<OttFactorDslConfigurer> ottConfigurerCustomizer) {
        OttFactorDslConfigurer configurer = factorDslConfigurerFactory.createConfigurer(AuthType.OTT);
        ottConfigurerCustomizer.customize(configurer);
        this.registeredFactorOptionsMap.put(AuthType.OTT, configurer.buildConcreteOptions());
        return this;
    }

    @Override
    public MfaDslConfigurer passkey(Customizer<PasskeyFactorDslConfigurer> passkeyConfigurerCustomizer) {
        PasskeyFactorDslConfigurer configurer = factorDslConfigurerFactory.createConfigurer(AuthType.PASSKEY);
        passkeyConfigurerCustomizer.customize(configurer);
        this.registeredFactorOptionsMap.put(AuthType.PASSKEY, configurer.buildConcreteOptions());
        return this;
    }

    @Override
    public MfaDslConfigurer recoveryFlow(Customizer<RecoveryDslConfigurer> recoveryConfigurerCustomizer) {
        // FactorDslConfigurerFactory가 AuthType.RECOVERY_CODE에 대해 RecoveryDslConfigurer 타입의 인스턴스를 반환.
        // RecoveryDslConfigurer 인터페이스는 OptionsBuilderDsl<RecoveryCodeFactorOptions, RecoveryDslConfigurer>를 확장.
        RecoveryDslConfigurer configurer = factorDslConfigurerFactory.createConfigurer(AuthType.RECOVERY_CODE);
        recoveryConfigurerCustomizer.customize(configurer);
        // configurer.buildConcreteOptions()는 RecoveryCodeFactorOptions를 반환.
        this.registeredFactorOptionsMap.put(AuthType.RECOVERY_CODE, configurer.buildConcreteOptions());
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
        Assert.notNull(policyProvider, "MfaPolicyProvider must be configured.");
        Assert.notNull(continuationHandler, "MfaContinuationHandler must be configured.");
        Assert.notNull(failureHandler, "MfaFailureHandler must be configured.");
        Assert.notNull(finalSuccessHandler, "FinalSuccessHandler must be configured.");
        // MFA 플로우에서는 1차 인증 후 추가 Factor가 없을 수도 있음 (정책에 따라 바로 성공 처리 가능)
        // 하지만 일반적으로 하나 이상의 Factor를 등록하므로, 이 Assert는 유지하거나 정책에 따라 조정.
        // Assert.isTrue(registeredFactorOptionsMap != null && !registeredFactorOptionsMap.isEmpty(), "At least one secondary MFA Factor must be registered using .ott(), .passkey() etc.");

        // AuthenticationFlowConfig.Builder의 모든 setter 메소드가 public이고 Builder 자신을 반환한다고 가정
        flowConfigBuilder
                .typeName(AuthType.MFA.name().toLowerCase())
                .order(this.order)
                // 이 부분은 AuthenticationFlowConfig.Builder에
                // public Builder primaryAuthenticationOptions(PrimaryAuthenticationOptions options)
                // 메소드가 정의되어 있어야 합니다.
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


