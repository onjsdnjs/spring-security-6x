package io.springsecurity.springsecurity6x.security.dsl.authentication;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * Form 로그인 DSL
 */
public final class FormAuthenticationDsl extends AbstractAuthenticationDsl {

    private String loginPage = "/login";
    private String loginProcessingUrl = "/login";
    private String usernameParameter = "username";
    private String passwordParameter = "password";
    private String defaultSuccessUrl = "/";
    private boolean alwaysUseDefaultSuccessUrl = false;
    private String failureUrl = "/login?error";
    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;
    private SecurityContextRepository securityContextRepository;

    public FormAuthenticationDsl loginPage(String loginPage) {
        this.loginPage = loginPage;
        return this;
    }

    public FormAuthenticationDsl loginProcessingUrl(String loginProcessingUrl) {
        this.loginProcessingUrl = loginProcessingUrl;
        return this;
    }

    public FormAuthenticationDsl usernameParameter(String usernameParameter) {
        this.usernameParameter = usernameParameter;
        return this;
    }

    public FormAuthenticationDsl passwordParameter(String passwordParameter) {
        this.passwordParameter = passwordParameter;
        return this;
    }

    public FormAuthenticationDsl defaultSuccessUrl(String defaultSuccessUrl) {
        this.defaultSuccessUrl = defaultSuccessUrl;
        return this;
    }

    public FormAuthenticationDsl alwaysUseDefaultSuccessUrl(boolean alwaysUse) {
        this.alwaysUseDefaultSuccessUrl = alwaysUse;
        return this;
    }

    public FormAuthenticationDsl failureUrl(String failureUrl) {
        this.failureUrl = failureUrl;
        return this;
    }

    public FormAuthenticationDsl successHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return this;
    }

    public FormAuthenticationDsl failureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return this;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.formLogin(form -> {
            form
                    .loginPage(loginPage)
                    .loginProcessingUrl(loginProcessingUrl)
                    .usernameParameter(usernameParameter)
                    .passwordParameter(passwordParameter)
                    .securityContextRepository(securityContextRepository)
                    .defaultSuccessUrl(defaultSuccessUrl, alwaysUseDefaultSuccessUrl)
                    .failureUrl(failureUrl);

            if (successHandler != null) {
                form.successHandler(successHandler);
            } else {
                form.successHandler(stateStrategy.successHandler());
            }

            if (failureHandler != null) {
                form.failureHandler(failureHandler);
            } else {
                form.failureHandler(stateStrategy.failureHandler());
            }
        });
    }
}

