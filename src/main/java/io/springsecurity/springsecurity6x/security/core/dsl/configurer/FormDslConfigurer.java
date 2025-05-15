package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

public interface FormDslConfigurer extends AuthenticationFactorConfigurer<FormOptions, FormDslConfigurer> {
    FormDslConfigurer loginPage(String loginPageUrl);
    FormDslConfigurer loginProcessingUrl(String loginProcessingUrl);
    FormDslConfigurer usernameParameter(String usernameParameter);
    FormDslConfigurer passwordParameter(String passwordParameter);
    FormDslConfigurer defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse);
    FormDslConfigurer failureUrl(String failureUrl);
    FormDslConfigurer permitAll();
    FormDslConfigurer successHandler(AuthenticationSuccessHandler successHandler);
    FormDslConfigurer failureHandler(AuthenticationFailureHandler failureHandler);
    FormDslConfigurer securityContextRepository(SecurityContextRepository repository);
    FormDslConfigurer rawFormLogin(SafeHttpFormLoginCustomizer customizer);
}
