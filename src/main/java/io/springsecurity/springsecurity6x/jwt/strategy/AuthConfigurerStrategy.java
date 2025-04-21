package io.springsecurity.springsecurity6x.jwt.strategy;

import io.springsecurity.springsecurity6x.jwt.properties.IntegrationAuthProperties;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface AuthConfigurerStrategy {
    void configureIfEnabled(HttpSecurity http, IntegrationAuthProperties props) throws Exception;
}
