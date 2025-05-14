package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.*;
import org.springframework.security.config.Customizer;

public interface SecurityPlatformDsl {

    SecurityPlatformDsl global(SafeHttpCustomizer customizer);

    // Customizer의 제네릭 타입을 *StepDslConfigurer로 변경
    IdentityStateDsl form(Customizer<FormStepDslConfigurer> customizer);

    IdentityStateDsl rest(Customizer<RestStepDslConfigurer> customizer);

    IdentityStateDsl ott(Customizer<OttStepDslConfigurer> customizer); // 타입 변경

    IdentityStateDsl passkey(Customizer<PasskeyStepDslConfigurer> customizer); // 타입 변경

    IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer);

    PlatformConfig build();
}

