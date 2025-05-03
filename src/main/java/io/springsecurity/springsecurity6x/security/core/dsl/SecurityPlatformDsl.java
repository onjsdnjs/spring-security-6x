package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Security Platform DSL의 엔트리 포인트입니다.
 * <p>
 * form, rest, ott, passkey, mfa 메서드를 통해 인증 플로우를 정의하고,
 * 이어서 IdentityStateDsl을 통해 session/jwt/oauth2 중 하나를 선택합니다.
 * 설정이 모두 완료되면 build()를 통해 PlatformConfig를 생성합니다.
 */
public interface SecurityPlatformDsl {

    /**
     * 모든 체인에서 공통으로 적용할 HttpSecurity 설정을 지정합니다.
     *
     * @param customizer HttpSecurity 커스터마이저
     * @return this
     */
    SecurityPlatformDsl global(Customizer<HttpSecurity> customizer);

    /**
     * Form 로그인 플로우를 정의합니다.
     *
     * @param customizer FormDslConfigurer 설정 람다
     * @return 상태 선택 DSL
     */
    IdentityStateDsl form(Customizer<FormDslConfigurer> customizer);

    /**
     * REST 로그인 플로우를 정의합니다.
     *
     * @param customizer RestDslConfigurer 설정 람다
     * @return 상태 선택 DSL
     */
    IdentityStateDsl rest(Customizer<RestDslConfigurer> customizer);

    /**
     * OTT 로그인 플로우를 정의합니다.
     *
     * @param customizer OttDslConfigurer 설정 람다
     * @return 상태 선택 DSL
     */
    IdentityStateDsl ott(Customizer<OttDslConfigurer> customizer);

    /**
     * Passkey(WebAuthn) 로그인 플로우를 정의합니다.
     *
     * @param customizer PasskeyDslConfigurer 설정 람다
     * @return 상태 선택 DSL
     */
    IdentityStateDsl passkey(Customizer<PasskeyDslConfigurer> customizer);

    /**
     * 다중 인증(MFA) 플로우를 정의합니다.
     *
     * @param customizer MfaDslConfigurer 설정 람다
     * @return 상태 선택 DSL
     */
    IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer);

    /**
     * DSL 설정이 모두 끝난 후 호출하여
     * 내부에 누적된 PlatformConfig를 생성합니다.
     *
     * @return 생성된 PlatformConfig
     */
    PlatformConfig build();
}

