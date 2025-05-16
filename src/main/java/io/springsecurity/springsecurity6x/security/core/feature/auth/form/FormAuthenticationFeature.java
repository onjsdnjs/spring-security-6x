package io.springsecurity.springsecurity6x.security.core.feature.auth.form;

import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.feature.auth.AbstractAuthenticationFeature;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class FormAuthenticationFeature extends AbstractAuthenticationFeature<FormOptions> {

    @Override
    public String getId() {
        return AuthType.FORM.name().toLowerCase();
    }

    @Override
    public int getOrder() {
        return 100;
    }

    @Override
    protected void configureHttpSecurity(HttpSecurity http, FormOptions opts,
                                         AuthenticationSuccessHandler successHandler,
                                         AuthenticationFailureHandler failureHandler) throws Exception {
        http.formLogin(form -> {
            form.loginPage(opts.getLoginPage())
                    .loginProcessingUrl(opts.getLoginProcessingUrl())
                    .usernameParameter(opts.getUsernameParameter())
                    .passwordParameter(opts.getPasswordParameter())
                    .failureUrl(opts.getFailureUrl())
                    .permitAll(opts.isPermitAll())
                    .successHandler(successHandler)
                    .failureHandler(failureHandler);

            if (opts.getSecurityContextRepository() != null) {
                form.securityContextRepository(opts.getSecurityContextRepository());
            }

            SafeHttpFormLoginCustomizer rawLogin = opts.getRawFormLoginCustomizers();
            if (rawLogin != null) {
                try {
                    rawLogin.customize(form);
                } catch (Exception e) {
                    throw new RuntimeException("Error customizing raw form login for " + getId(), e);
                }
            }
        });
    }
}
