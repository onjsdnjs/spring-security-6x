package io.springsecurity.springsecurity6x.jwt.config;

import io.springsecurity.springsecurity6x.jwt.dsl.ExternalTokenDslConfigurer;
import io.springsecurity.springsecurity6x.jwt.properties.IntegrationAuthProperties;
import io.springsecurity.springsecurity6x.jwt.enums.AuthType;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ott.InMemoryOneTimeTokenService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.concurrent.TimeUnit;

@Configuration
public class MultiSecurityConfig {

    private final JwtDecoder jwtDecoder;
    private final IntegrationAuthProperties properties;
    private final ApplicationContext applicationContext;

    public MultiSecurityConfig(
            JwtDecoder jwtDecoder, IntegrationAuthProperties properties, ApplicationContext applicationContext) {
        this.jwtDecoder = jwtDecoder;
        this.properties = properties;
        this.applicationContext = applicationContext;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return switch (properties.getTokenType()) {
            case EXTERNAL -> configureExternal(http);
            case INTERNAL -> configureInternal(http);
        };
    }

    @Bean
    public InMemoryOneTimeTokenService tokenService() {
        return new InMemoryOneTimeTokenService();
    }

    private SecurityFilterChain configureExternal(HttpSecurity http) throws Exception {

        http.csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login/**", "/ott/**", "/css/**").permitAll()
                .anyRequest().authenticated());
        http
                .with(ExternalTokenDslConfigurer.jwt(properties,applicationContext), configurer -> configurer
                .tokenPrefix("Bearer ")
                .accessTokenValidity(1, TimeUnit.HOURS)
                .refreshTokenValidity(7, TimeUnit.DAYS)
                .loginEndpoint("/api/auth/login")
                .logoutEndpoint("/api/auth/logout")
                .refreshEndpoint("/api/auth/refresh")
                .rolesClaim("roles")
                .enableRefreshToken(true)
        );
        applyAuthTypes(http);

        return http.build();
    }

    private SecurityFilterChain configureInternal(HttpSecurity http) throws Exception {

        http.csrf(AbstractHttpConfigurer::disable);
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder)));
        applyAuthTypes(http);

        return http.build();
    }

    private void applyAuthTypes(HttpSecurity http) throws Exception {
        if (properties.isAuthEnabled(AuthType.OTT)) {
            http
                .oneTimeTokenLogin(ott -> ott.tokenGeneratingUrl("/ott/generate")       // 토큰 생성 요청
                        .defaultSubmitPageUrl("/login/ott*")  // 토큰 포함 링크(/login/ott?token=…)
                        .showDefaultSubmitPage(true)
                        .tokenService(tokenService()));

        } else if (properties.isAuthEnabled(AuthType.PASSKEY)) {
            http
                .webAuthn(web -> web
                        .rpName("DemoPasskey App")
                        .rpId("localhost")
                        .allowedOrigins("http://localhost:8080"));
        }
    }
}



