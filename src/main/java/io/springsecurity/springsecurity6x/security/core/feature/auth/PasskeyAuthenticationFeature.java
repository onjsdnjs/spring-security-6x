package io.springsecurity.springsecurity6x.security.core.feature.auth;

import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class PasskeyAuthenticationFeature extends AbstractAuthenticationFeature<PasskeyOptions> {

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
                                         AuthenticationSuccessHandler successHandler,
                                         AuthenticationFailureHandler failureHandler) throws Exception {
        http.webAuthn(web -> {
            web.rpName(opts.getRpName())
                    .rpId(opts.getRpId())
                    .allowedOrigins(opts.getAllowedOrigins());
        });
    }

    @Override
    protected String determineDefaultFailureUrl(PasskeyOptions options) {
        // 예: return options.getFailureUrl() != null ? options.getFailureUrl() : "/loginPasskey?error_passkey_default";
        return "/loginPasskey?error_passkey_default";
    }
}

