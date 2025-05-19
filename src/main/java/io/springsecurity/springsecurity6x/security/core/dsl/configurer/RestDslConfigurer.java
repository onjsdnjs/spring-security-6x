package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.RestAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

public interface RestDslConfigurer extends AuthenticationFactorConfigurer<RestOptions, RestAsepAttributes, RestDslConfigurer> {
}

