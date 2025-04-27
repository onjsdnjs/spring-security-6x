package io.springsecurity.springsecurity6x.security.config;

import io.springsecurity.springsecurity6x.security.dsl.AuthIntegrationPlatformConfigurer;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final TokenService tokenService;
    private final OneTimeTokenGenerationSuccessHandler ottHandler;
    private final OneTimeTokenService oneTimeTokenService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        http.csrf(csrf -> csrf.ignoringRequestMatchers(new AntPathRequestMatcher("/h2-console/**")))
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))

                .authorizeHttpRequests(authReq -> authReq
                        .requestMatchers("/api/register").permitAll()
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().permitAll())
//                .authenticationManager(authenticationManager)

                .with(AuthIntegrationPlatformConfigurer.custom(), identity -> identity
                        .rest(rest -> rest
                                .loginProcessingUrl("/api/auth/login")
                        )
                        .form(form -> form
                                .loginPage("/login")
                        )
                        .ott(ott -> ott
                                .loginProcessingUrl("/login/ott")
                                .tokenService(oneTimeTokenService)
                                .tokenGenerationSuccessHandler(ottHandler)
                        )
                        .passkey(passkey -> passkey
                                .rpName("SecureApp")
                                .rpId("localhost")
                                .allowedOrigins("http://localhost:8080")
                        )
                        .state(state -> state
                                .jwt(tokenService)
                                .tokenPrefix("Bearer-MyApp ")
                                .accessTokenValidity(2 * 3600_000)    // 2시간
                                .refreshTokenValidity(14 * 24 * 3600_000) // 2주
                                .enableRefreshToken(true)
                        )
                );


        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return (web) -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
