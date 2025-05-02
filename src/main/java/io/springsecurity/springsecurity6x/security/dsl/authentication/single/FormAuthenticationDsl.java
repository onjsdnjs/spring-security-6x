package io.springsecurity.springsecurity6x.security.dsl.authentication.single;

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

    }

    public FormAuthenticationDsl loginProcessingUrl(String loginProcessingUrl) {
        this.loginProcessingUrl = loginProcessingUrl;

    }

    public FormAuthenticationDsl usernameParameter(String usernameParameter) {
        this.usernameParameter = usernameParameter;

    }

    public FormAuthenticationDsl passwordParameter(String passwordParameter) {
        this.passwordParameter = passwordParameter;

    }

    public FormAuthenticationDsl defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUseDefaultSuccessUrl) {
        this.defaultSuccessUrl = defaultSuccessUrl;
        this.alwaysUseDefaultSuccessUrl = alwaysUseDefaultSuccessUrl;

    }

    public FormAuthenticationDsl alwaysUseDefaultSuccessUrl(boolean alwaysUse) {
        this.alwaysUseDefaultSuccessUrl = alwaysUse;

    }

    public FormAuthenticationDsl failureUrl(String failureUrl) {
        this.failureUrl = failureUrl;

    }

    public FormAuthenticationDsl successHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;

    }

    public FormAuthenticationDsl failureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;

    }

    public FormAuthenticationDsl securityContextRepository(SecurityContextRepository securityContextRepository) {
        this.securityContextRepository = securityContextRepository;

    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.formLogin(form -> {
            form
                    .loginPage(loginPage)
                    .loginProcessingUrl(loginProcessingUrl)
                    .usernameParameter(usernameParameter)
                    .passwordParameter(passwordParameter)
                    .defaultSuccessUrl(defaultSuccessUrl, alwaysUseDefaultSuccessUrl)
                    .failureUrl(failureUrl);

            if (successHandler != null) {
                form.successHandler(successHandler);
            } else {
                form.successHandler(authenticationHandlers.successHandler());
            }
            if (failureHandler != null) {
                form.failureHandler(failureHandler);
            } else {
                form.failureHandler(authenticationHandlers.failureHandler());
            }

            if (securityContextRepository != null) {
                form.securityContextRepository(securityContextRepository);
            }
        });
    }
}

