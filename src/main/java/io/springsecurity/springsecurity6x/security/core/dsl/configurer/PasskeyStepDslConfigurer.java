package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.dsl.common.OptionsBuilderDsl;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.Set;

public interface PasskeyStepDslConfigurer extends StepDslConfigurer, OptionsBuilderDsl<PasskeyOptions, PasskeyStepDslConfigurer> {
    PasskeyStepDslConfigurer processingUrl(String url);
    PasskeyStepDslConfigurer rpName(String name);
    PasskeyStepDslConfigurer rpId(String id);
    PasskeyStepDslConfigurer allowedOrigins(String... origins);
    PasskeyStepDslConfigurer allowedOrigins(Set<String> origins);
    PasskeyStepDslConfigurer targetUrl(String url);
    PasskeyStepDslConfigurer successHandler(AuthenticationSuccessHandler handler);
    PasskeyStepDslConfigurer failureHandler(AuthenticationFailureHandler handler);
}
