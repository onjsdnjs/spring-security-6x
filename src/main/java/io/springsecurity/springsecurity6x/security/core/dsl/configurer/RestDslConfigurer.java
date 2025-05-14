package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.dsl.common.OptionsBuilderDsl;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;


public interface RestDslConfigurer extends OptionsBuilderDsl<RestOptions, RestDslConfigurer> {
    RestDslConfigurer loginProcessingUrl(String url);
    RestDslConfigurer targetUrl(String url);
    RestDslConfigurer successHandler(AuthenticationSuccessHandler handler);
    RestDslConfigurer failureHandler(AuthenticationFailureHandler handler);
    RestDslConfigurer securityContextRepository(SecurityContextRepository repository);
}

