package io.springsecurity.springsecurity6x.jwt.configurer.authentication;

import io.springsecurity.springsecurity6x.jwt.configurer.state.AuthenticationStateStrategy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class PasskeyAuthenticationConfigurer implements AuthenticationEntryConfigurer {

    private String rpName = "SecureApp";
    private String rpId = "localhost";
    private String[] allowedOrigins = new String[]{"http://localhost:8080"};
    private AuthenticationStateStrategy stateStrategy;

    public void rpName(String rpName) {
        this.rpName = rpName;
    }

    public void rpId(String rpId) {
        this.rpId = rpId;
    }

    public void origin(String... origins) {
        this.allowedOrigins = origins;
    }

    @Override
    public void setStateStrategy(AuthenticationStateStrategy stateStrategy) {
        this.stateStrategy = stateStrategy;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.webAuthn(web -> web
                .rpName(rpName)
                .rpId(rpId)
                .allowedOrigins(allowedOrigins));
    }
}
