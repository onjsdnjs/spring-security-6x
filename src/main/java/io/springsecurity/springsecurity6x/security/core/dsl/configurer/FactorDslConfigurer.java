package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * 개별 MFA Factor의 기술적 설정을 위한 DSL 인터페이스.
 * 각 Factor (Passkey, OTT 등)는 이 인터페이스를 구현합니다.
 */
public interface FactorDslConfigurer<O extends FactorAuthenticationOptions, S extends FactorDslConfigurer<O, S>> {
    S processingUrl(String url);
    S successHandler(AuthenticationSuccessHandler handler);
    S failureHandler(AuthenticationFailureHandler handler);
    O buildAuthenticationOptions(); // 구체적인 Options 타입 반환
}