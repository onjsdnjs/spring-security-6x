package io.springsecurity.springsecurity6x.jwt.strategy;

import io.springsecurity.springsecurity6x.jwt.properties.AuthContextProperties;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public interface AuthContextStrategy {

    boolean supports(AuthContextProperties props);
    SecurityFilterChain configure(HttpSecurity http) throws Exception;
}

