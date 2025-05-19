package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.mfa.options.PrimaryAuthenticationOptions;
import org.springframework.security.config.Customizer;

/**
 * MFA 플로우의 1차 인증(ID/PW) 설정을 위한 DSL 인터페이스.
 */
public interface PrimaryAuthDslConfigurer {
    // FormDslConfigurer가 ASEP 설정을 가질 수 있으므로, Customizer를 통해 간접적으로 ASEP 설정 가능
    PrimaryAuthDslConfigurer formLogin(Customizer<FormDslConfigurer> formLoginCustomizer);
    // RestDslConfigurer가 ASEP 설정을 가질 수 있으므로, Customizer를 통해 간접적으로 ASEP 설정 가능
    PrimaryAuthDslConfigurer restLogin(Customizer<RestDslConfigurer> restLoginCustomizer);
    PrimaryAuthenticationOptions buildOptions();
}
