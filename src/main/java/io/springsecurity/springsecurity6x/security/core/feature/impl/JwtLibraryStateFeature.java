package io.springsecurity.springsecurity6x.security.core.feature.impl;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import io.springsecurity.springsecurity6x.security.core.server.jwt.JwtLibraryConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class JwtLibraryStateFeature implements StateFeature {
    private final JwtLibraryConfigurer configurer;

    public JwtLibraryStateFeature(JwtLibraryConfigurer configurer) {
        this.configurer = configurer;
    }

    @Override
    public String getId() {
        return "jwt";
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext ctx) throws Exception {
        configurer.init(http);
        configurer.configure(http);
    }
}
