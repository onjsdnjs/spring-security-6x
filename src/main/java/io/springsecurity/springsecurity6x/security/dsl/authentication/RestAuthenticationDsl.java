package io.springsecurity.springsecurity6x.security.dsl.authentication;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

public final class RestAuthenticationDsl extends AbstractAuthenticationDsl {

    private String loginProcessingUrl = "/api/auth/login";
    private String defaultSuccessUrl = "/";
    private String failureUrl = "/login?error";
    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;
    private SecurityContextRepository securityContextRepository;

    public RestAuthenticationDsl loginProcessingUrl(String url) {
        this.loginProcessingUrl = url;
        return this;
    }

    public RestAuthenticationDsl successHandler(AuthenticationSuccessHandler handler) {
        this.successHandler = handler;
        return this;
    }

    public RestAuthenticationDsl failureHandler(AuthenticationFailureHandler handler) {
        this.failureHandler = handler;
        return this;
    }

    @Override
    public void init(HttpSecurity http) {
        super.init(http);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.with(new RestAuthenticationConfigurer(), rest -> {
            rest
                .loginProcessingUrl(loginProcessingUrl)
                .defaultSuccessUrl(defaultSuccessUrl)
                .failureUrl(failureUrl);

            if (successHandler != null) {
                rest.successHandler(successHandler);
            } else {
                rest.successHandler(authenticationHandlers.successHandler());
            }

            if (failureHandler != null) {
                rest.failureHandler(failureHandler);
            } else {
                rest.failureHandler(authenticationHandlers.failureHandler());
            }

            if (securityContextRepository != null) {
                rest.securityContextRepository(securityContextRepository);
            }
        });
    }
}
