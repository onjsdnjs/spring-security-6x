package io.springsecurity.springsecurity6x.security.init.configurer;

import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurerImpl;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class JwtStateConfigurer implements StateConfigurer {
    private final JwtStateConfigurerImpl delegate;

    public JwtStateConfigurer(JwtStateConfigurerImpl delegate) {
        this.delegate = delegate;
    }

    @Override
    public void apply(HttpSecurity http) throws Exception {
        http.with(delegate, Customizer.withDefaults());
    }
}

