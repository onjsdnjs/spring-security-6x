package io.springsecurity.springsecurity6x.security.config;

import io.springsecurity.springsecurity6x.security.configurer.SecurityIntegrationConfigurer;
import io.springsecurity.springsecurity6x.security.handler.SecurityLogoutSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.TokenLogoutHandler;
import io.springsecurity.springsecurity6x.security.ott.EmailOneTimeTokenService;
import io.springsecurity.springsecurity6x.security.ott.EmailService;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ott.InMemoryOneTimeTokenService;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final TokenService tokenService;
    private final JwtDecoder jwtDecoder;
    private final OneTimeTokenGenerationSuccessHandler ottGenSuccessHandler;
    private final OneTimeTokenService oneTimeTokenService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        http.csrf(csrf -> csrf.ignoringRequestMatchers(new AntPathRequestMatcher("/h2-console/**")))
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                .logout(logout -> logout
                        .addLogoutHandler(new TokenLogoutHandler(tokenService))
                        .logoutSuccessHandler(new SecurityLogoutSuccessHandler()))

                .authorizeHttpRequests(authReq -> authReq
                        .requestMatchers("/api/register").permitAll()
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().permitAll())
                .authenticationManager(authenticationManager);

        http.with(new SecurityIntegrationConfigurer(http), configurer -> configurer
                        .authentication(auth -> auth
                                .form(form -> form
                                        .loginProcessingUrl("/api/auth/login")
                                        .authenticationManager(authenticationManager)
                                )
                                .ott(ott -> ott
                                        .loginProcessingUrl("/login/ott")
                                        .defaultSubmitPageUrl("/login/ott")
                                        .showDefaultSubmitPage(false)
                                        .tokenGeneratingUrl("/ott/generate")
                                        .tokenService(oneTimeTokenService)
                                        .tokenGenerationSuccessHandler(ottGenSuccessHandler)
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
                                /*.useSession(session -> {})*/
                        )
                        .authorizationServer(auth -> {})
                        .resourceServer(resource -> resource
                                .jwtDecoder(jwtDecoder)
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
