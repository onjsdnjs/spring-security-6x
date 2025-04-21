package io.springsecurity.springsecurity6x.jwt.strategy;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public interface TokenSecurityStrategy {
    SecurityFilterChain configure(HttpSecurity http) throws Exception;
}

