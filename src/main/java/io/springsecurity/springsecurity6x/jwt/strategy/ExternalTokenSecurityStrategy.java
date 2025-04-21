package io.springsecurity.springsecurity6x.jwt.strategy;

import io.springsecurity.springsecurity6x.jwt.dsl.ExternalTokenDslConfigurer;
import io.springsecurity.springsecurity6x.jwt.properties.IntegrationAuthProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class ExternalTokenSecurityStrategy implements TokenSecurityStrategy{

    private final IntegrationAuthProperties integrationAuthProperties;
    private final ApplicationContext ctx;
    private final List<AuthConfigurerStrategy> authStrategies;
    private final AuthenticationProvider authenticationProvider;

    @Override
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login/**", "/ott/**", "/css/**").permitAll()
                        .anyRequest().authenticated())
                .authenticationProvider(authenticationProvider);

        http.with(ExternalTokenDslConfigurer.jwt(integrationAuthProperties, ctx), configurer -> configurer
                .tokenPrefix("Bearer ")
                .accessTokenValidity(1, TimeUnit.HOURS)
                .refreshTokenValidity(7, TimeUnit.DAYS)
                .loginEndpoint("/api/auth/login")
                .logoutEndpoint("/api/auth/logout")
                .refreshEndpoint("/api/auth/refresh")
                .rolesClaim("roles")
                .enableRefreshToken(true)
        );

        for (AuthConfigurerStrategy strategy : authStrategies) {
            strategy.configureIfEnabled(http, integrationAuthProperties);
        }

        return http.build();
    }
}

