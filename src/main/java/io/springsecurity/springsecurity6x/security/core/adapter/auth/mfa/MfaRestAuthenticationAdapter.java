package io.springsecurity.springsecurity6x.security.core.adapter.auth.mfa;

import io.springsecurity.springsecurity6x.security.core.adapter.auth.BaseRestAuthenticationAdapter;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.MfaRestAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

/**
 * MFA REST 인증 어댑터
 */
public final class MfaRestAuthenticationAdapter extends BaseRestAuthenticationAdapter<MfaRestAuthenticationConfigurer<HttpSecurity>> {

    @Override
    public String getId() {
        return AuthType.MFA_REST.name().toLowerCase();
    }

    @Override
    protected MfaRestAuthenticationConfigurer createConfigurer() {
        return new MfaRestAuthenticationConfigurer();
    }

    @Override
    protected void configureRestAuthentication(MfaRestAuthenticationConfigurer configurer,
                                               RestOptions opts,
                                               AuthenticationSuccessHandler successHandler,
                                               AuthenticationFailureHandler failureHandler) {
        configurer.loginProcessingUrl(opts.getLoginProcessingUrl())
                .successHandler(opts.getSuccessHandler() != null ? opts.getSuccessHandler() : successHandler)
                .failureHandler(opts.getFailureHandler() != null ? opts.getFailureHandler() : failureHandler);
    }

    @Override
    protected void configureSecurityContext(MfaRestAuthenticationConfigurer configurer,
                                            RestOptions opts) {
        configurer.securityContextRepository(opts.getSecurityContextRepository());
    }
}