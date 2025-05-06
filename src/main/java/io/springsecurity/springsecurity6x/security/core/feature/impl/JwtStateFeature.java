package io.springsecurity.springsecurity6x.security.core.feature.impl;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import io.springsecurity.springsecurity6x.security.core.server.jwt.JwtConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class JwtStateFeature implements StateFeature {

    private JwtConfigurer configurer;

    public JwtStateFeature(){}

    public JwtStateFeature(JwtConfigurer configurer) {
        this.configurer = configurer;
    }

    @Override
    public String getId() {
        return "jwt";
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext ctx) throws Exception {
        if(configurer != null){
            configurer.init(http);
            configurer.configure(http);
        }
    }
}
