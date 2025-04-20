package io.springsecurity.springsecurity6x.jwt.config;

import io.springsecurity.springsecurity6x.jwt.annotation.EnableJwtSecurity;
import io.springsecurity.springsecurity6x.jwt.JwtDslConfigurer;
import io.springsecurity.springsecurity6x.jwt.annotation.RefreshTokenStore;
import io.springsecurity.springsecurity6x.jwt.dsl.JwtSecurityConfigurer;
import io.springsecurity.springsecurity6x.jwt.tokenservice.TokenService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableJwtSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, TokenService tokenService, RefreshTokenStore store, AuthenticationManager authManager) throws Exception {

            http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**", "/h2-console/**").permitAll()
                        .anyRequest().authenticated())
                .with(JwtSecurityConfigurer.jwt(), configurer -> configurer
                        .tokenService(tokenService)
                        .refreshTokenStore(store)
                        .authenticationManager(authManager)
                        .tokenPrefix("Bearer ")
                        .accessTokenValidity(1, TimeUnit.HOURS)
                        .refreshTokenValidity(7, TimeUnit.DAYS)
                        .loginEndpoint("/api/auth/login")
                        .logoutEndpoint("/api/auth/logout")
                        .refreshEndpoint("/api/auth/refresh")
                        .rolesClaim("roles")
                        .scopesClaim("scopes")
                        .enableRefreshToken(true)
                        .authorizeScopes(scope -> scope
                                .require("read", "/api/read/**")
                                .require("write", "/api/write/**")
                        )
                );

        return http.build();
    }
}
