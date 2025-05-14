package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.OptionsBuilderDsl; // 추가
import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions; // 추가
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.AdaptiveDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.RetryPolicyDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaContinuationHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.config.Customizer;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public interface MfaDslConfigurer {

    MfaDslConfigurer order(int order);

    MfaDslConfigurer primaryAuthentication(Customizer<PrimaryAuthDslConfigurer> primaryAuthConfig);

    MfaDslConfigurer mfaContinuationHandler(MfaContinuationHandler continuationHandler);

    /**
     * 사용 가능한 MFA Factor들을 등록하고 각 Factor의 기술적 설정을 정의합니다.
     *
     * @param factorType 등록할 Factor의 AuthType
     * @param factorConfigurerCustomizer 해당 Factor 설정을 위한 Customizer.
     * S는 OptionsBuilderDsl을 구현하는 특정 FactorDslConfigurer 인터페이스여야 합니다.
     * O는 해당 Factor의 Options 타입입니다.
     */
    // <C extends FactorDslConfigurer> MfaDslConfigurer registerFactor(AuthType factorType, Customizer<C> factorConfigurer); // 이전 시그니처
    <O extends FactorAuthenticationOptions, S extends OptionsBuilderDsl<O, S>>
    MfaDslConfigurer registerFactor(AuthType factorType, Customizer<S> factorConfigurerCustomizer); // 수정된 시그니처


    MfaDslConfigurer mfaFailureHandler(MfaFailureHandler failureHandler);

    MfaDslConfigurer finalSuccessHandler(AuthenticationSuccessHandler handler);

    MfaDslConfigurer policyProvider(MfaPolicyProvider policyProvider);

    MfaDslConfigurer defaultRetryPolicy(Customizer<RetryPolicyDslConfigurer> c);

    MfaDslConfigurer defaultAdaptivePolicy(Customizer<AdaptiveDslConfigurer> c);

    MfaDslConfigurer defaultDeviceTrustEnabled(boolean enable);

    AuthenticationFlowConfig build();
}