package io.springsecurity.springsecurity6x.security.core.adapter.state.oauth2;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

public class OAuth2StateConfigurer extends AbstractHttpConfigurer<OAuth2StateConfigurer, HttpSecurity> {

    public void init(HttpSecurity http) {
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
    }
}
