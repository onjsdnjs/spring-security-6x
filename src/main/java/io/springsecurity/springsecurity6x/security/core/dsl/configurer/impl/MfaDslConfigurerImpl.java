package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.MfaDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RestDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factor.ott.OttFactorDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factor.passkey.PasskeyFactorDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factory.FactorDslConfigurerFactory;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.RecoveryDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.util.Assert;

public class MfaDslConfigurerImpl implements MfaDslConfigurer {
    private final AuthenticationFlowConfig.Builder flowConfigBuilder;
    private final FactorDslConfigurerFactory factorDslConfigurerFactory; // Ott, Passkey 등을 위해 유지 가능
    private final ApplicationContext applicationContext;

    private FactorAuthenticationOptions primaryAuthFactorOptions; // 1차 인증 Factor의 Options 저장
    // ... (기타 필드: policyProvider, handlers, registeredFactorOptionsMap 등)

    public MfaDslConfigurerImpl(AuthenticationFlowConfig.Builder flowConfigBuilder, ApplicationContext applicationContext) {
        this.flowConfigBuilder = flowConfigBuilder;
        this.applicationContext = applicationContext;
        this.factorDslConfigurerFactory = new FactorDslConfigurerFactory(applicationContext);
    }

    // ... (order, policyProvider, handlers 등 기존 메소드 구현은 이전 답변 참고) ...

    @Override
    public MfaDslConfigurer rest(Customizer<RestDslConfigurer> restConfigurerCustomizer) {
        // RestDslConfigurer는 Options 빌딩 인터페이스여야 함.
        // RestDslOptionsBuilderConfigurer는 해당 인터페이스의 구현체.
        RestDslOptionsBuilderConfigurer configurer = new RestDslOptionsBuilderConfigurer();
        restConfigurerCustomizer.customize(configurer);
        // MFA 플로우에서 첫 번째 스텝(1차 인증)으로 간주하고 저장
        this.primaryAuthFactorOptions = configurer.buildConcreteOptions();
        // 필요시, 이 primaryAuthFactorOptions를 registeredFactorOptionsMap에도 특정 AuthType (예: AuthType.REST_PRIMARY)으로 추가할 수 있음
        // 또는 AuthenticationFlowConfig.Builder에 primaryAuthFactorOptions를 직접 설정하는 메소드 사용
        return this;
    }

    @Override
    public MfaDslConfigurer ott(Customizer<OttFactorDslConfigurer> ottConfigurerCustomizer) {
        // FactorDslConfigurerFactory가 OttFactorDslConfigurer 타입의 인스턴스를 반환한다고 가정
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
        // RecoveryDslConfigurer 및 그 구현체(예: RecoveryCodeFactorDslConfigurerImpl)가 필요
        // FactorDslConfigurerFactory가 RecoveryDslConfigurer 타입의 인스턴스를 반환한다고 가정
        RecoveryDslConfigurer configurer = factorDslConfigurerFactory.createConfigurer(AuthType.RECOVERY_CODE); // AuthType.RECOVERY_CODE 가정
        recoveryConfigurerCustomizer.customize(configurer);
        this.registeredFactorOptionsMap.put(AuthType.RECOVERY_CODE, configurer.buildConcreteOptions());
        return this;
    }

    @Override
    public AuthenticationFlowConfig build() {
        Assert.notNull(primaryAuthFactorOptions, "Primary authentication (e.g., using .rest()) must be configured for MFA flow.");
        // ... (기존 Assert 검증 로직 유지) ...

        flowConfigBuilder
                .typeName(AuthType.MFA.name().toLowerCase())
                .order(this.order)
                // primaryAuthenticationOptions 필드는 AuthenticationFlowConfig.Builder에
                // PrimaryAuthenticationOptions 타입을 받는 setter가 있거나,
                // FactorAuthenticationOptions의 공통 타입을 받는 setter가 있어야 함.
                // 이전 설계에서는 PrimaryAuthenticationOptions 타입의 setter가 있었음.
                // 만약 primaryAuthFactorOptions가 FactorAuthenticationOptions 타입이라면 바로 전달 가능.
                // 현재 primaryAuthFactorOptions는 FactorAuthenticationOptions 타입이므로,
                // AuthenticationFlowConfig.Builder에 .primaryAuthFactor(FactorAuthenticationOptions) 와 같은 메소드가 필요하거나,
                // .primaryAuthenticationOptions(PrimaryAuthenticationOptions)가 여전히 유효하다면,
                // this.primaryAuthFactorOptions를 PrimaryAuthenticationOptions으로 캐스팅하거나 타입을 맞춰야 함.
                // 여기서는 this.primaryAuthFactorOptions가 이미 PrimaryAuthenticationOptions 타입이라고 가정하고,
                // build() 메소드에서 .primaryAuthenticationOptions()를 사용한다고 가정합니다.
                // 또는, 1차 인증도 registeredFactorOptionsMap에 특정 키로 넣고, Builder에서 이를 구분하여 처리.
                // 가장 간단한 방법은 AuthenticationFlowConfig.Builder에 primaryAuthFactorOptions(FactorAuthenticationOptions options) 추가.
                .primaryAuthenticationOptionsFromFactor(this.primaryAuthFactorOptions) // Builder에 이런 메소드가 있다고 가정
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


