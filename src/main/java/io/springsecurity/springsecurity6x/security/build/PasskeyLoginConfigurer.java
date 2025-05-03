/*
package io.springsecurity.springsecurity6x.security.build;

import io.springsecurity.springsecurity6x.security.core.feature.option.PasskeyOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.init.AuthenticationConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

*/
/**
 * Passkey 인증 방식 구성 Configurer.
 * 현재는 기본 securityMatcher 설정만 구성되어 있으며,
 * WebAuthn 인증 필터는 이후 단계에서 통합 구현 필요.
 *//*

@Slf4j
public class PasskeyLoginConfigurer implements IdentitySecurityConfigurer {

    @Override
    public boolean supports(AuthenticationConfig config) {
        return AuthType.PASSKEY.name().equalsIgnoreCase(config.type()) &&
                config.options() instanceof PasskeyOptions;
    }

    @Override
    public void configure(HttpSecurity http, AuthenticationConfig config) throws Exception {
        PasskeyOptions options = (PasskeyOptions) config.options();
        if (options.matchers() != null && !options.matchers().isEmpty()) {
            http.securityMatcher(options.matchers().toArray(new String[0]));
        } else {
            http.securityMatcher("/**");
        }

        http.webAuthn(web -> web
                .rpName(options.rpName())
                .rpId(options.rpId())
                .allowedOrigins(options.allowedOrigins())
        );
    }

    @Override
    public void init(HttpSecurity http) throws Exception {

    }

    @Override
    public int order() {
        return 20;
    }
}

*/
