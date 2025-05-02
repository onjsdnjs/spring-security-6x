package io.springsecurity.springsecurity6x.security.dsl.authentication.single;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public final class PasskeyAuthenticationDsl extends AbstractAuthenticationDsl {
    private String rpName = "SecureApp";
    private String rpId = "localhost";
    private String[] allowedOrigins = new String[]{"http://localhost:8080"};

    public PasskeyAuthenticationDsl rpName(String n) { this.rpName = n; return this; }
    public PasskeyAuthenticationDsl rpId(String id) { this.rpId = id; return this; }
    public PasskeyAuthenticationDsl allowedOrigins(String... origins) { this.allowedOrigins = origins; return this; }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.webAuthn(web -> web
                .rpName(rpName)
                .rpId(rpId)
                .allowedOrigins(allowedOrigins)
        );
    }
}


