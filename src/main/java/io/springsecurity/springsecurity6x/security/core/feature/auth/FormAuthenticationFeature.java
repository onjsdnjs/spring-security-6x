package io.springsecurity.springsecurity6x.security.core.feature.auth;

import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
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
                    // defaultSuccessUrl은 successHandler가 설정되면 일반적으로 무시됨.
                    // 필요시 successHandler 내부에서 이 URL을 사용하도록 로직 추가 가능.
                    // .defaultSuccessUrl(opts.getDefaultSuccessUrl(), opts.isAlwaysUseDefaultSuccessUrl())
                    .failureUrl(opts.getFailureUrl()) // SimpleUrlAuthenticationFailureHandler가 사용
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

    @Override
    protected String determineDefaultFailureUrl(FormOptions options) {
        return options.getFailureUrl() != null ? options.getFailureUrl() : "/loginForm?error_form_default";
    }
}
