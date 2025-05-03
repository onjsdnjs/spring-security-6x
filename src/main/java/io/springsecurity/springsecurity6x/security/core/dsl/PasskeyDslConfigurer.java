package io.springsecurity.springsecurity6x.security.core.dsl;

/**
 * Passkey(WebAuthn) 로그인 관련 DSL 설정을 정의하는 인터페이스입니다.
 * <p>
 * 사용자는 이 DSL을 통해 Passkey 인증 엔드포인트, Relying Party 정보, 허용된 출처 등을
 * 설정할 수 있으며, 이를 기반으로 플랫폼이 HttpSecurity에 Passkey 인증 필터를 적용합니다.
 */
public interface PasskeyDslConfigurer {

    PasskeyDslConfigurer matchers(String... patterns);

    PasskeyDslConfigurer rpName(String name);

    PasskeyDslConfigurer rpId(String id);

    PasskeyDslConfigurer allowedOrigins(String... origins);
}

