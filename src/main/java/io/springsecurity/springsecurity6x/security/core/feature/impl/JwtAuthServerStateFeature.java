package io.springsecurity.springsecurity6x.security.core.feature.impl;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import io.springsecurity.springsecurity6x.security.core.server.authserver.JwtAuthServerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class JwtAuthServerStateFeature implements StateFeature {
    private final JwtAuthServerConfigurer configurer;

    public JwtAuthServerStateFeature(JwtAuthServerConfigurer configurer) {
        this.configurer = configurer;
    }

    @Override
    public String getId() {
        return "oauth2";
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext ctx) throws Exception {
        configurer.init(http);
        configurer.configure(http);
    }
}
