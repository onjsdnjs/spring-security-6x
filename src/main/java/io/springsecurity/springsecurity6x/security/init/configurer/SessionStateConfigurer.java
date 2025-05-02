package io.springsecurity.springsecurity6x.security.init.configurer;

import io.springsecurity.springsecurity6x.security.dsl.state.session.SessionStateConfigurerImpl;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class SessionStateConfigurer implements StateConfigurer {
    private final SessionStateConfigurerImpl delegate;

    public SessionStateConfigurer(SessionStateConfigurerImpl delegate) {
        this.delegate = delegate;
    }

    @Override
    public void apply(HttpSecurity http) throws Exception {
        http.with(delegate, Customizer.withDefaults());
    }
}

