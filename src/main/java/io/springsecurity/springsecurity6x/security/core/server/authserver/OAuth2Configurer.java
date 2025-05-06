package io.springsecurity.springsecurity6x.security.core.server.authserver;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;

public class OAuth2Configurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    public void init(HttpSecurity http) {
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
    }
}
