package io.springsecurity.springsecurity6x.security.core.mfa.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.FormDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.OttDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.PasskeyDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RestDslConfigurer;
import org.springframework.security.config.Customizer;

/**
 * MfaDslConfigurer 개편판
 */
public interface MfaDslConfigurer {
    /** form 인증 스텝 추가 */
    MfaDslConfigurer form(Customizer<FormDslConfigurer> customizer);
    /** REST 인증 스텝 추가 */
    MfaDslConfigurer rest(Customizer<RestDslConfigurer> customizer);
    /** OTT(One-Time Token) 인증 스텝 추가 */
    MfaDslConfigurer ott(Customizer<OttDslConfigurer> customizer);
    /** Passkey(WebAuthn) 인증 스텝 추가 */
    MfaDslConfigurer passkey(Customizer<PasskeyDslConfigurer> customizer);

    /** 전체 MFA 플로우의 실행 우선순위 지정 */
    MfaDslConfigurer order(int order);

    /** MFA 인증 실행 Url */
    MfaDslConfigurer loginProcessUrl(String url);

    /** 재시도 정책 설정 */
    MfaDslConfigurer retryPolicy(Customizer<RetryPolicyDslConfigurer> c);
    /** Adaptive(조건부) 정책 설정 */
    MfaDslConfigurer adaptive(Customizer<AdaptiveDslConfigurer> c);
    /** “이 디바이스 기억하기” 활성화 여부 */
    MfaDslConfigurer deviceTrust(boolean enable);
    /** 복구(Recovery) 워크플로우 설정 */
    MfaDslConfigurer recoveryFlow(Customizer<RecoveryDslConfigurer> c);

    /** 내부에 모아둔 설정으로 AuthenticationFlowConfig 를 완성하여 반환 */
    AuthenticationFlowConfig build();
}