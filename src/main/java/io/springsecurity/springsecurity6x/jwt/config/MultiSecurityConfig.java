package io.springsecurity.springsecurity6x.jwt.config;

import io.springsecurity.springsecurity6x.jwt.annotation.EnableJwtSecurity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableJwtSecurity
public class MultiSecurityConfig {

    private final TokenSecurityStrategyConfigurer strategyConfigurer;

    public MultiSecurityConfig(TokenSecurityStrategyConfigurer strategyConfigurer) {
        this.strategyConfigurer = strategyConfigurer;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return strategyConfigurer.configure(http);
    }
}




