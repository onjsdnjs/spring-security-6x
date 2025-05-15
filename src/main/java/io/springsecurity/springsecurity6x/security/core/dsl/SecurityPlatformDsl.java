package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.*;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface SecurityPlatformDsl {

    SecurityPlatformDsl global(SafeHttpCustomizer<HttpSecurity> customizer);

    // Customizer의 제네릭 타입을 *StepDslConfigurer로 변경
    IdentityStateDsl form(Customizer<FormDslConfigurer> customizer);

    IdentityStateDsl rest(Customizer<RestDslConfigurer> customizer);

    IdentityStateDsl ott(Customizer<OttDslConfigurer> customizer); // 타입 변경

    IdentityStateDsl passkey(Customizer<PasskeyDslConfigurer> customizer); // 타입 변경

    IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer);

    PlatformConfig build();
}

