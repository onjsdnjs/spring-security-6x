package io.springsecurity.springsecurity6x.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
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
    public PlatformConfig platformDslConfig(IdentityDslRegistry<HttpSecurity> registry) throws Exception {

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
                        .exceptionHandling(e -> e.authenticationEntryPoint(new TokenAuthenticationEntryPoint(objectMapper))) // objectMapper 주입
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
                        ))
                .form(form -> {
                    form
                            .loginPage("/loginForm")
                            .loginProcessingUrl("/login")
                            .successHandler(jwtEmittingAndMfaAwareSuccessHandler)
                            .failureHandler(singleAuthFailureHandler("/loginForm?error"))
                            .permitAll()
                            .order(100)
                            .asep(asepForm -> {
                                log.debug("PlatformSecurityConfig: Configuring ASEP options for FormLogin.");
                            });
                }).session(Customizer.withDefaults())

                .ott(ott -> {
                    ott
                            .tokenService(emailOneTimeTokenService)
                            .tokenGeneratingUrl("/api/ott/generate")
                            .loginProcessingUrl("/login/ott")
                            .successHandler(jwtEmittingAndMfaAwareSuccessHandler)
                            .failureHandler(singleAuthFailureHandler("/loginOtt?error_ott"))
                            .order(110)
                            .asep(asepOtt -> {
                                log.debug("PlatformSecurityConfig: Configuring ASEP options for OTT.");
                            });
                }).session(Customizer.withDefaults())

                .passkey(passkey -> {
                    passkey
                            .rpId(rpId)
                            .rpName("Spring Security 6x IDP")
                            .assertionOptionsEndpoint("/webauthn/assertion/options")
                            .loginProcessingUrl("/login/webauthn")
                            .successHandler(jwtEmittingAndMfaAwareSuccessHandler)
                            .failureHandler(singleAuthFailureHandler("/loginPasskey?error_passkey"))
                            .order(120)
                            .asep(asepPasskey -> {
                                log.debug("PlatformSecurityConfig: Configuring ASEP options for Passkey.");
                            });
                }).session(Customizer.withDefaults())

                /*.rest(rest -> {
                    rest
                            .loginProcessingUrl("/api/auth/login")
                            .successHandler(jwtEmittingAndMfaAwareSuccessHandler)
                            .failureHandler(singleAuthFailureHandler("/loginForm?error_rest")) // 예시
                            .order(130)
                            .asep(asepRest -> {
                                log.debug("PlatformSecurityConfig: Configuring ASEP options for REST API login.");
                            });
                }).jwt(Customizer.withDefaults())
*/
                .mfa(mfa -> {
                    mfa.asep(asepMfaGlobal -> {
                        log.debug("PlatformSecurityConfig: Configuring global ASEP options for MFA flow.");
                        // asepMfaGlobal.exceptionArgumentResolver(...) 등으로 설정
                    });
                    mfa
                            .primaryAuthentication(primaryAuth -> primaryAuth
                                    .restLogin(rest -> rest
                                            .loginProcessingUrl("/api/auth/login")
                                            .successHandler(mfaCapableRestSuccessHandler)
                                            .failureHandler(mfaAuthenticationFailureHandler)
                                            .asep(asepMfaPrimaryRest -> {
                                                log.debug("PlatformSecurityConfig: Configuring ASEP options for MFA Primary REST.");
                                            })
                                    )
                            )
                            .ott(ottFactor -> {
                                ottFactor.tokenService(emailOneTimeTokenService)
                                        .loginProcessingUrl("/login/mfa-ott")
                                        .successHandler(mfaStepBasedSuccessHandler)
                                        .failureHandler(mfaAuthenticationFailureHandler)
                                        .asep(asepMfaOtt -> {
                                            log.debug("PlatformSecurityConfig: Configuring ASEP options for MFA OTT Factor.");
                                        });
                            })
                            .passkey(passkeyFactor -> {
                                passkeyFactor.rpId(rpId)
                                        .rpName("Spring Security 6x IDP MFA")
                                        .assertionOptionsEndpoint("/api/mfa/assertion/options")
                                        .loginProcessingUrl("/login/mfa-passkey")
                                        .successHandler(mfaStepBasedSuccessHandler)
                                        .failureHandler(mfaAuthenticationFailureHandler)
                                        .asep(asepMfaPasskey -> {
                                            log.debug("PlatformSecurityConfig: Configuring ASEP options for MFA Passkey Factor.");
                                        });
                            })
                            .finalSuccessHandler(jwtEmittingAndMfaAwareSuccessHandler)
                            .policyProvider(applicationContext.getBean(MfaPolicyProvider.class))
                            .mfaFailureHandler(mfaAuthenticationFailureHandler)
                            .order(20);
                })
                .jwt(Customizer.withDefaults())
                .build();
    }

    // PlatformSecurityConfig의 다른 @Bean 정의들은 그대로 유지
    // (예: globalConfigurers() 빈 - GlobalConfigurer, FlowConfigurer 등 정적 Configurer 제공)
    // (예: SecurityPlatform, PlatformBootstrap 등)
}