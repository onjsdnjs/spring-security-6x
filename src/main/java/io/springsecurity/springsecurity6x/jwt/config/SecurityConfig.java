package io.springsecurity.springsecurity6x.jwt.config;

import io.springsecurity.springsecurity6x.jwt.JwtProperties;
import io.springsecurity.springsecurity6x.jwt.annotation.EnableJwtSecurity;
import io.springsecurity.springsecurity6x.jwt.annotation.RefreshTokenStore;
import io.springsecurity.springsecurity6x.jwt.dsl.JwtSecurityConfigurer;
import io.springsecurity.springsecurity6x.jwt.tokenservice.TokenService;
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

import static org.springframework.security.core.userdetails.User.withUsername;

@Configuration
@EnableJwtSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final ApplicationContext applicationContext;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtProperties jwtProperties) throws Exception {

        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**", "/h2-console/**", "/login/**").permitAll()
                        .anyRequest().authenticated())
                .authenticationProvider(authenticationProvider())
                .with(JwtSecurityConfigurer.jwt(jwtProperties,applicationContext), configurer -> configurer
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

    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService());
        return daoAuthenticationProvider;
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("onjsdnjs@gmail.com")
                .password("1111")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);

    }
}
