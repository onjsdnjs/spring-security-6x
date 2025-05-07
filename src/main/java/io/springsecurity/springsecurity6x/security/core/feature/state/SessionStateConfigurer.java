package io.springsecurity.springsecurity6x.security.core.feature.state;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

public class SessionStateConfigurer extends AbstractHttpConfigurer<SessionStateConfigurer, HttpSecurity> {

    @Override
    public void init(HttpSecurity http) {
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
    }
}
