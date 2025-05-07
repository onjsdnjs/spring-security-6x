package io.springsecurity.springsecurity6x.security.core.feature.state.oauth2;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class OAuth2StateFeature implements StateFeature {

    private OAuth2StateConfigurer configurer;

    public OAuth2StateFeature(){}

    public OAuth2StateFeature(OAuth2StateConfigurer configurer) {
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
