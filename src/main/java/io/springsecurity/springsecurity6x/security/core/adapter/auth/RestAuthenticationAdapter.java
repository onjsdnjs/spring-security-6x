package io.springsecurity.springsecurity6x.security.core.adapter.auth;

import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.RestAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public final class RestAuthenticationAdapter extends AbstractAuthenticationAdapter<RestOptions> {

    @Override
    public String getId() {
        return AuthType.REST.name().toLowerCase();
    }

    @Override
    public int getOrder() {
        return 200;
    }

    @Override
    protected void configureHttpSecurity(HttpSecurity http, RestOptions opts,
                                         AuthenticationSuccessHandler successHandler,
                                         AuthenticationFailureHandler failureHandler) throws Exception {
        http.with(new RestAuthenticationConfigurer(), rest -> {
            rest.loginProcessingUrl(opts.getLoginProcessingUrl())
                    .successHandler(opts.getSuccessHandler() == null ? successHandler:opts.getSuccessHandler())
                    .failureHandler(opts.getFailureHandler() == null ? failureHandler:opts.getFailureHandler());

            if (opts.getSecurityContextRepository() != null) {
                rest.securityContextRepository(opts.getSecurityContextRepository());
            }
        });
    }
}

