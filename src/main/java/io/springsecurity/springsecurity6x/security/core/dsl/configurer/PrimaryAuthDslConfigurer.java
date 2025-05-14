package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.mfa.options.PrimaryAuthenticationOptions;
import org.springframework.security.config.Customizer;

/**
 * MFA 플로우의 1차 인증(ID/PW) 설정을 위한 DSL 인터페이스.
 */
public interface PrimaryAuthDslConfigurer {
    PrimaryAuthDslConfigurer formLogin(Customizer<FormDslConfigurer> formLoginCustomizer);
    PrimaryAuthDslConfigurer restLogin(Customizer<RestDslConfigurer> restLoginCustomizer);
    PrimaryAuthenticationOptions buildOptions();
}
