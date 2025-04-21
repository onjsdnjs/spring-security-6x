package io.springsecurity.springsecurity6x.jwt.strategy;

import io.springsecurity.springsecurity6x.jwt.enums.AuthType;
import io.springsecurity.springsecurity6x.jwt.properties.IntegrationAuthProperties;
import org.springframework.security.authentication.ott.InMemoryOneTimeTokenService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;

@Component
public class PasskeyConfigurerStrategy implements AuthConfigurerStrategy {

    @Override
    public void configureIfEnabled(HttpSecurity http, IntegrationAuthProperties props) throws Exception {
        if (props.isAuthEnabled(AuthType.PASSKEY)) {
            http.webAuthn(web -> web
                    .rpName("DemoPasskey App")
                    .rpId("localhost")
                    .allowedOrigins("http://localhost:8080"));
        }
    }
}

