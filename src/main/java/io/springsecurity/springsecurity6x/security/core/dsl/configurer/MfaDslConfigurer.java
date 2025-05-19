package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.MfaAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SecurityConfigurerDsl;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.AdaptiveDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.RetryPolicyDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaContinuationHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public interface MfaDslConfigurer extends SecurityConfigurerDsl { // SecurityConfigurerDsl 마커 인터페이스 (선택적)
    MfaDslConfigurer order(int order);

    // 각 Factor DSL을 위한 메소드 (이 내부에서 각 Factor의 Configurer가 ASEP 설정을 가질 수 있도록 설계)
    MfaDslConfigurer form(Customizer<FormDslConfigurer> formConfigurer); // MFA의 한 단계로 Form 인증 사용
    MfaDslConfigurer rest(Customizer<RestDslConfigurer> restConfigurer); // MFA의 한 단계로 Rest 인증 사용
    MfaDslConfigurer ott(Customizer<OttDslConfigurer> ottConfigurer);   // MFA의 한 단계로 OTT 인증 사용
    MfaDslConfigurer passkey(Customizer<PasskeyDslConfigurer> passkeyConfigurer); // MFA의 한 단계로 Passkey 인증 사용

    MfaDslConfigurer recoveryFlow(Customizer<RecoveryCodeDslConfigurer> recoveryConfigurerCustomizer); // RecoveryCodeDslConfigurer 정의 필요
    MfaDslConfigurer mfaContinuationHandler(MfaContinuationHandler continuationHandler);
    MfaDslConfigurer mfaFailureHandler(MfaFailureHandler failureHandler);
    MfaDslConfigurer finalSuccessHandler(AuthenticationSuccessHandler handler);
    MfaDslConfigurer policyProvider(MfaPolicyProvider policyProvider);
    MfaDslConfigurer defaultRetryPolicy(Customizer<RetryPolicyDslConfigurer> c);
    MfaDslConfigurer defaultAdaptivePolicy(Customizer<AdaptiveDslConfigurer> c);
    MfaDslConfigurer defaultDeviceTrustEnabled(boolean enable);
    AuthenticationFlowConfig build(); // 최종적으로 AuthenticationFlowConfig 객체 반환

    // MFA 플로우 전체에 대한 ASEP 설정을 위한 DSL 메소드
    MfaDslConfigurer asep(Customizer<MfaAsepAttributes> mfaAsepAttributesCustomizer) throws Exception;

    // Primary Authentication (MFA 이전의 1차 인증) 설정
    MfaDslConfigurer primaryAuthentication(Customizer<PrimaryAuthDslConfigurer> primaryAuthConfig);
}