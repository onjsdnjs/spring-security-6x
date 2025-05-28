package io.springsecurity.springsecurity6x.security.core.adapter.auth;

import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.RestAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.handler.AbstractMfaAuthenticationSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.PlatformAuthenticationFailureHandler;
import io.springsecurity.springsecurity6x.security.handler.PlatformAuthenticationSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.UnifiedAuthenticationFailureHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

/**
 * 단일 REST 인증 어댑터
 */
@Component
public final class RestAuthenticationAdapter extends BaseRestAuthenticationAdapter<RestAuthenticationConfigurer<HttpSecurity>> {

    @Override
    public String getId() {
        return AuthType.REST.name().toLowerCase();
    }

    @Override
    protected RestAuthenticationConfigurer createConfigurer() {
        return new RestAuthenticationConfigurer();
    }

    @Override
    protected void configureRestAuthentication(RestAuthenticationConfigurer configurer,
                                               RestOptions opts,
                                               PlatformAuthenticationSuccessHandler successHandler,
                                               PlatformAuthenticationFailureHandler failureHandler) {

        configurer.loginProcessingUrl(opts.getLoginProcessingUrl())
                .successHandler(successHandler)
                .failureHandler(failureHandler);
    }

    @Override
    protected void configureSecurityContext(RestAuthenticationConfigurer configurer,
                                            RestOptions opts) {
        configurer.securityContextRepository(opts.getSecurityContextRepository());
    }
}