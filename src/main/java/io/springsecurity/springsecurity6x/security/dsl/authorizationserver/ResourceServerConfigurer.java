package io.springsecurity.springsecurity6x.security.dsl.authorizationserver;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;

public class ResourceServerConfigurer {

    private JwtDecoder jwtDecoder;

    public ResourceServerConfigurer jwtDecoder(JwtDecoder decoder) {
        this.jwtDecoder = decoder;
        return this;
    }

    public void configure(HttpSecurity http) throws Exception {
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder)));
    }
}
