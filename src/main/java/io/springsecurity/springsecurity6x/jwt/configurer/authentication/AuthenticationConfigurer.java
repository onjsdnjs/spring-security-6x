package io.springsecurity.springsecurity6x.jwt.configurer.authentication;

import io.springsecurity.springsecurity6x.jwt.configurer.state.AuthenticationStateStrategy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface AuthenticationConfigurer {
    void stateStrategy(AuthenticationStateStrategy strategy);
    void configure(HttpSecurity http) throws Exception;
}

