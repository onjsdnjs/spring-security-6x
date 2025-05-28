package io.springsecurity.springsecurity6x.security.core.adapter.auth;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.handler.PlatformAuthenticationFailureHandler;
import io.springsecurity.springsecurity6x.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class PasskeyAuthenticationAdapter extends AbstractAuthenticationAdapter<PasskeyOptions> {

    @Override
    public String getId() {
        return AuthType.PASSKEY.name().toLowerCase();
    }

    @Override
    public int getOrder() {
        return 400;
    }

    @Override
    protected void configureHttpSecurity(HttpSecurity http, PasskeyOptions opts,
                                         AuthenticationFlowConfig currentFlow,
                                         PlatformAuthenticationSuccessHandler successHandler,
                                         PlatformAuthenticationFailureHandler failureHandler) throws Exception {

        http.webAuthn(web -> {
            web.rpName(opts.getRpName())
                    .rpId(opts.getRpId())
                    .allowedOrigins(opts.getAllowedOrigins());
        });
    }
}

