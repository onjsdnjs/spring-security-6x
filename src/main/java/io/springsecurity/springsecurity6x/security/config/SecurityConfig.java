package io.springsecurity.springsecurity6x.security.config;

import io.springsecurity.springsecurity6x.security.configurer.SecurityIntegrationConfigurer;
import io.springsecurity.springsecurity6x.security.tokenservice.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ott.InMemoryOneTimeTokenService;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final TokenService tokenService;
    private final JwtDecoder jwtDecoder;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authReq -> authReq
                        .requestMatchers("/", "/login*", "/api/auth/login", "/login/**","/ott/sent","/register").permitAll()
                        .anyRequest().authenticated())
                .authenticationManager(authenticationManager)
                .with(new SecurityIntegrationConfigurer(), configurer -> configurer
                        .authentication(auth -> auth
                                .form(form -> form
                                        .loginProcessingUrl("/api/auth/login")
                                        .authenticationManager(authenticationManager)
                                )
                                .ott(ott -> ott
                                        .loginProcessingUrl("/login/ott")
                                        .tokenService(new InMemoryOneTimeTokenService())
                                )
                                .passkey(passkey -> passkey
                                        .origin("http://localhost:8080")
                                )
                        )
                        .state(state -> state
                                .useJwt(jwt -> jwt
                                        .tokenService(tokenService)
                                        .tokenPrefix("Bearer ")
                                )
                        )
                        .authorizationServer(auth -> {})
                        .resourceServer(resource -> resource
                                .jwtDecoder(jwtDecoder)
                        )
                );

        return http.build();
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
