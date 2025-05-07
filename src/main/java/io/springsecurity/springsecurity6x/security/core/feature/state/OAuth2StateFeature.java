package io.springsecurity.springsecurity6x.security.core.feature.state;

import io.springsecurity.springsecurity6x.security.core.context.DefaultPlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import io.springsecurity.springsecurity6x.security.core.issuer.oauth2.OAuth2Issuer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class OAuth2StateFeature implements StateFeature {

    private OAuth2Issuer configurer;

    public OAuth2StateFeature(){}

    public OAuth2StateFeature(OAuth2Issuer configurer) {
        this.configurer = configurer;
    }

    @Override
    public String getId() {
        return "oauth2";
    }

    @Override
    public void apply(HttpSecurity http, DefaultPlatformContext ctx) throws Exception {
        configurer.init(http);
        configurer.configure(http);
    }
}
