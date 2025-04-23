package io.springsecurity.springsecurity6x.security.config;

import io.springsecurity.springsecurity6x.security.configurer.SecurityIntegrationConfigurer;
import io.springsecurity.springsecurity6x.security.tokenservice.TokenService;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ott.InMemoryOneTimeTokenService;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final TokenService tokenService;
    private final JwtDecoder jwtDecoder;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        http.csrf(csrf -> csrf
                .ignoringRequestMatchers(new AntPathRequestMatcher("/h2-console/**")))
                .headers(headers -> headers
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable)
                )
                .authorizeHttpRequests(authReq -> authReq
                        .requestMatchers("/api/register").permitAll()
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().permitAll())
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
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .addLogoutHandler((req, res, auth) -> {
                            // 쿠키 삭제
                            Cookie accessCookie = new Cookie("accessToken", null);
                            accessCookie.setMaxAge(0);
                            accessCookie.setPath("/");
                            res.addCookie(accessCookie);

                            Cookie refreshCookie = new Cookie("refreshToken", null);
                            refreshCookie.setMaxAge(0);
                            refreshCookie.setPath("/");
                            res.addCookie(refreshCookie);
                        })
                        .logoutSuccessUrl("/loginForm")
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request, response, authException) -> {
                            // 인증이 필요한 리소스에 토큰이 없거나 만료되었을 때
                            response.sendRedirect(request.getContextPath() + "/loginForm");
                        })
                )
                // (선택) 403(Access Denied) 발생 시
                .exceptionHandling(ex -> ex
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.sendRedirect(request.getContextPath() + "/access-denied");
                        })
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
