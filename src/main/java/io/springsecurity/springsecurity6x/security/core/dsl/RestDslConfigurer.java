package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.dsl.common.CommonSecurityDsl;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;


public interface RestDslConfigurer extends CommonSecurityDsl<RestDslConfigurer> {
    RestDslConfigurer loginProcessingUrl(String url);
    RestDslConfigurer successHandler(AuthenticationSuccessHandler handler);
    RestDslConfigurer failureHandler(AuthenticationFailureHandler handler);
    RestDslConfigurer securityContextRepository(SecurityContextRepository repository);
}

