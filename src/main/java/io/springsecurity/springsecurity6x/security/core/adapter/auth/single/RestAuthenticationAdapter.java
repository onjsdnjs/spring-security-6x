package io.springsecurity.springsecurity6x.security.core.adapter.auth.single;

import io.springsecurity.springsecurity6x.security.core.adapter.auth.BaseRestAuthenticationAdapter;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.RestAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
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
                                               AuthenticationSuccessHandler successHandler,
                                               AuthenticationFailureHandler failureHandler) {
        configurer.loginProcessingUrl(opts.getLoginProcessingUrl())
                .successHandler(opts.getSuccessHandler() != null ? opts.getSuccessHandler() : successHandler)
                .failureHandler(opts.getFailureHandler() != null ? opts.getFailureHandler() : failureHandler);
    }

    @Override
    protected void configureSecurityContext(RestAuthenticationConfigurer configurer,
                                            RestOptions opts) {
        configurer.securityContextRepository(opts.getSecurityContextRepository());
    }
}