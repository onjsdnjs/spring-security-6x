package io.springsecurity.springsecurity6x.security.core.adapter.state.oauth2;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.adapter.StateAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class OAuth2StateAdapter implements StateAdapter {

    private OAuth2StateConfigurer configurer;

    public OAuth2StateAdapter(){}

    public OAuth2StateAdapter(OAuth2StateConfigurer configurer) {
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
