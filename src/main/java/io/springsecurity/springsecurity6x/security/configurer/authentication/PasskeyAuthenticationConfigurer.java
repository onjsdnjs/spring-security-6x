package io.springsecurity.springsecurity6x.security.configurer.authentication;

import io.springsecurity.springsecurity6x.security.configurer.state.AuthenticationStateStrategy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class PasskeyAuthenticationConfigurer  implements AuthenticationConfigurer{

    private String rpName = "SecureApp";
    private String rpId = "localhost";
    private String[] allowedOrigins = new String[]{"http://localhost:8080"};
    private AuthenticationStateStrategy stateStrategy;

    public PasskeyAuthenticationConfigurer rpName(String rpName) {
        this.rpName = rpName;
        return this;
    }

    public PasskeyAuthenticationConfigurer rpId(String rpId) {
        this.rpId = rpId;
        return this;
    }

    public PasskeyAuthenticationConfigurer origin(String... origins) {
        this.allowedOrigins = origins;
        return this;
    }

    public void stateStrategy(AuthenticationStateStrategy stateStrategy) {
        this.stateStrategy = stateStrategy;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .webAuthn(web -> web
                        .rpName(rpName)
                        .rpId(rpId)
                        .allowedOrigins(allowedOrigins)
                );
    }
}

