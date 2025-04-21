package io.springsecurity.springsecurity6x.jwt.config;

import io.springsecurity.springsecurity6x.jwt.annotation.EnableJwtSecurity;
import io.springsecurity.springsecurity6x.jwt.dsl.ExternalTokenDslConfigurer;
import io.springsecurity.springsecurity6x.jwt.properties.IntegrationAuthProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableJwtSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final ApplicationContext applicationContext;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, IntegrationAuthProperties integrationAuthProperties) throws Exception {

        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**", "/h2-console/**", "/login/**").permitAll()
                        .anyRequest().authenticated())
                .authenticationProvider(authenticationProvider)
                .with(ExternalTokenDslConfigurer.jwt(integrationAuthProperties,applicationContext), configurer -> configurer
                        .tokenPrefix("Bearer ")
                        .accessTokenValidity(1, TimeUnit.HOURS)
                        .refreshTokenValidity(7, TimeUnit.DAYS)
                        .loginEndpoint("/api/auth/login")
                        .logoutEndpoint("/api/auth/logout")
                        .refreshEndpoint("/api/auth/refresh")
                        .enableRefreshToken(true)
                        .rolesClaim("roles")
                );

        return http.build();
    }


}
