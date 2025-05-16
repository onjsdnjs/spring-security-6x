package io.springsecurity.springsecurity6x.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.bootstrap.TokenServiceConfiguration;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.IdentityDslRegistry;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.exceptionhandling.TokenAuthenticationEntryPoint;
import io.springsecurity.springsecurity6x.security.handler.JwtEmittingAndMfaAwareSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaAuthenticationFailureHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaCapableRestSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaStepBasedSuccessHandler;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.service.ott.EmailOneTimeTokenService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import java.util.Map;

@Slf4j
@Configuration
@RequiredArgsConstructor
@Import(TokenServiceConfiguration.class)
public class PlatformSecurityConfig {

    private final ApplicationContext applicationContext;
    private final AuthContextProperties authContextProperties;
    private final ObjectMapper objectMapper;
    private final EmailOneTimeTokenService emailOneTimeTokenService;
    private final MfaCapableRestSuccessHandler mfaCapableRestSuccessHandler;
    private final MfaStepBasedSuccessHandler mfaStepBasedSuccessHandler;
    private final MfaAuthenticationFailureHandler mfaAuthenticationFailureHandler;
    private final JwtEmittingAndMfaAwareSuccessHandler jwtEmittingAndMfaAwareSuccessHandler;

    private AuthenticationFailureHandler singleAuthFailureHandler(String failureUrl) {
        return new SimpleUrlAuthenticationFailureHandler(failureUrl);
    }

    @Bean
    public PlatformConfig platformDslConfig(IdentityDslRegistry registry) {
        String rpId = applicationContext.getEnvironment().getProperty("spring.security.webauthn.relyingparty.id", "localhost");

        return registry
                .global(http -> http
                        .csrf(AbstractHttpConfigurer::disable)
                        .authorizeHttpRequests(authReq -> authReq
                                .requestMatchers(
                                        "/css/**", "/js/**", "/images/**", "/favicon.ico",
                                        "/", "/authMode",
                                        "/loginForm", "/register",
                                        "/loginOtt", "/ott/sent",
                                        "/loginPasskey",
                                        "/mfa/select-factor", "/mfa/verify/ott", "/mfa/verify/passkey", "/mfa/failure",
                                        "/api/register", "/api/auth/login", "/api/auth/refresh",
                                        "/api/ott/generate", "/webauthn/assertion/options",
                                        "/api/mfa/select-factor", "/api/mfa/request-ott-code", "/api/mfa/assertion/options"
                                ).permitAll()
                                .requestMatchers("/users", "/api/users").hasRole("USER")
                                .requestMatchers("/admin", "/api/admin/**").hasRole("ADMIN")
                                .anyRequest().authenticated()
                        )
                        .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                        .sessionManagement(session -> session
                                .sessionCreationPolicy(authContextProperties.isAllowMultipleLogins() ?
                                        SessionCreationPolicy.IF_REQUIRED : SessionCreationPolicy.ALWAYS)
                                .maximumSessions(authContextProperties.isAllowMultipleLogins() ? authContextProperties.getMaxConcurrentLogins() : 1)
                                .expiredUrl("/loginForm?expired")
                        )
                        .exceptionHandling(e -> e.authenticationEntryPoint(new TokenAuthenticationEntryPoint())) // objectMapper 주입하도록 수정 가능
                        .logout(logout -> logout
                                .logoutUrl("/api/auth/logout")
                                .addLogoutHandler(applicationContext.getBean("jwtLogoutHandler", LogoutHandler.class))
                                .logoutSuccessHandler((request, response, authentication) -> {
                                    response.setStatus(HttpServletResponse.SC_OK);
                                    response.setContentType("application/json;charset=UTF-8");
                                    objectMapper.writeValue(response.getWriter(), Map.of("message", "로그아웃 되었습니다.", "redirectUrl", "/loginForm"));
                                })
                                .invalidateHttpSession(true)
                                .deleteCookies("JSESSIONID")
                        )
                )
                .form(form -> form
                        .loginPage("/loginForm")
                        .loginProcessingUrl("/login")
                        .successHandler(jwtEmittingAndMfaAwareSuccessHandler)
                        .failureHandler(singleAuthFailureHandler("/loginForm?error"))
                        .order(10)
                ).session(Customizer.withDefaults())

                .ott(ott -> ott
                        .tokenService(emailOneTimeTokenService)
                        .tokenGeneratingUrl("/api/ott/generate")
                        .loginProcessingUrl("/login/ott")
                        .successHandler(jwtEmittingAndMfaAwareSuccessHandler)
                        .failureHandler(singleAuthFailureHandler("/loginOtt?error"))
                        .order(20)
                ).session(Customizer.withDefaults())

                .passkey(passkey -> passkey
                        .rpId(rpId)
                        .assertionOptionsEndpoint("/api/passkey/assertion/options")
                        .loginProcessingUrl("/login/webauthn")
                        .successHandler(jwtEmittingAndMfaAwareSuccessHandler)
                        .failureHandler(singleAuthFailureHandler("/loginPasskey?error"))
                        .order(30)
                ).session(Customizer.withDefaults())

                .mfa(mfa -> mfa
                        .form(rest -> rest
                                .loginProcessingUrl("/api/auth/login")
                                .successHandler(mfaCapableRestSuccessHandler)
                        )
                        .ott(ott -> ott
                                .tokenService(emailOneTimeTokenService)
                                .loginProcessingUrl("/login/mfa-ott")
                                .successHandler(mfaStepBasedSuccessHandler)
                                .failureHandler(mfaAuthenticationFailureHandler)
                        )
                        .passkey(passkey -> passkey
                                .rpId(rpId)
                                .loginProcessingUrl("/login/mfa-passkey")
                                .successHandler(mfaStepBasedSuccessHandler)
                                .failureHandler(mfaAuthenticationFailureHandler)
                        )
                        .finalSuccessHandler(mfaStepBasedSuccessHandler)
                        .policyProvider(applicationContext.getBean(MfaPolicyProvider.class))
                        .mfaFailureHandler(mfaAuthenticationFailureHandler)
                        .order(5)
                )
                .jwt(Customizer.withDefaults())
                .build();
    }
}