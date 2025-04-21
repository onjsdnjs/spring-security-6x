package io.springsecurity.springsecurity6x.jwt.configurer.authentication;

import io.springsecurity.springsecurity6x.jwt.strategy.AuthenticationStateStrategy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface AuthenticationEntryConfigurer {
    void setStateStrategy(AuthenticationStateStrategy strategy);
    void configure(HttpSecurity http) throws Exception;
}

