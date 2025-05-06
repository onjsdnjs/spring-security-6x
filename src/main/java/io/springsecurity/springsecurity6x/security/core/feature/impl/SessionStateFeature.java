package io.springsecurity.springsecurity6x.security.core.feature.impl;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import io.springsecurity.springsecurity6x.security.core.state.session.SessionStateConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class SessionStateFeature implements StateFeature {

    private SessionStateConfigurer configurer;

    public SessionStateFeature(){}

    public SessionStateFeature(SessionStateConfigurer configurer) {
        this.configurer = configurer;
    }

    @Override
    public String getId() {
        return "session";
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext ctx) throws Exception {
        configurer.init(http);
        configurer.configure(http);
    }
}
