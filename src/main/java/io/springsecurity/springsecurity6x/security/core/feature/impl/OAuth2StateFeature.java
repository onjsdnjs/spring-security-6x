package io.springsecurity.springsecurity6x.security.core.feature.impl;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import io.springsecurity.springsecurity6x.security.core.server.authserver.OAuth2Configurer;
import io.springsecurity.springsecurity6x.security.core.server.jwt.JwtConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class OAuth2StateFeature implements StateFeature {

    private OAuth2Configurer configurer;

    public OAuth2StateFeature(){}

    public OAuth2StateFeature(OAuth2Configurer configurer) {
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
