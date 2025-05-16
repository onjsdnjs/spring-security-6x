package io.springsecurity.springsecurity6x.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.bootstrap.TokenServiceConfiguration;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.IdentityDslRegistry;
import io.springsecurity.springsecurity6x.security.exceptionhandling.TokenAuthenticationEntryPoint;
import io.springsecurity.springsecurity6x.security.handler.MfaAuthenticationFailureHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaCapableRestSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaStepBasedSuccessHandler;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.service.ott.EmailOneTimeTokenService;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Configuration
@RequiredArgsConstructor
@Import(TokenServiceConfiguration.class) // TokenService 관련 Bean 설정 Import
public class PlatformSecurityConfig {

    private final ApplicationContext applicationContext;
    private final AuthContextProperties authContextProperties;
    private final ObjectMapper objectMapper;
    private final EmailOneTimeTokenService emailOneTimeTokenService; // 자동 설정된 Bean
    private final TokenService tokenService; // 자동 설정된 Bean
    private final MfaCapableRestSuccessHandler mfaCapableRestSuccessHandler;
    private final MfaStepBasedSuccessHandler mfaStepBasedSuccessHandler;
    private final MfaAuthenticationFailureHandler mfaAuthenticationFailureHandler;


    // 단일 인증 성공 시 JWT를 발급하는 핸들러 (POJO로 생성하여 사용)
    private AuthenticationSuccessHandler singleAuthSuccessHandlerWithJwt() {
        return new JwtEmittingSingleAuthSuccessHandler(tokenService, objectMapper, "/");
    }

    // 단일 인증 실패 핸들러 (POJO)
    private AuthenticationFailureHandler singleAuthFailureHandler(String failureUrl) {
        return new SimpleUrlAuthenticationFailureHandler(failureUrl);
    }

    @Bean
    public PlatformConfig appSpecificPlatformDslConfig(IdentityDslRegistry registry) {
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
                                        org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED :
                                        org.springframework.security.config.http.SessionCreationPolicy.ALWAYS)
                                .sessionFixation().migrateSession()
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
                        .successHandler(singleAuthSuccessHandlerWithJwt())
                        .failureHandler(singleAuthFailureHandler("/loginForm?error"))
                ).session(Customizer.withDefaults())

                .ott(ott -> ott
                        .tokenService(emailOneTimeTokenService)
                        .tokenGeneratingUrl("/api/ott/generate")
                        .loginProcessingUrl("/login/ott")
                        .successHandler(singleAuthSuccessHandlerWithJwt())
                        .failureHandler(singleAuthFailureHandler("/loginOtt?error"))
                ).session(Customizer.withDefaults())

                .passkey(passkey -> passkey
                        .rpId(rpId)
                        .assertionOptionsEndpoint("/api/passkey/assertion/options")
                        .loginProcessingUrl("/login/webauthn")
                        .successHandler(singleAuthSuccessHandlerWithJwt())
                        .failureHandler(singleAuthFailureHandler("/loginPasskey?error"))
                ).session(Customizer.withDefaults())

                .mfa(mfa -> mfa
                        .rest(rest -> rest
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
                        .finalSuccessHandler(mfaStepBasedSuccessHandler) // 모든 MFA 단계 완료 후
                )
                .jwt(Customizer.withDefaults())
                .build();
    }

    // 단일 인증 성공 시 JWT를 발급하는 핸들러 (POJO 예시)
    @Slf4j
    @RequiredArgsConstructor
    private static class JwtEmittingSingleAuthSuccessHandler implements AuthenticationSuccessHandler {
        private final TokenService tokenService; // 생성자를 통해 주입 (POJO이므로 Spring DI 아님)
        private final ObjectMapper objectMapper;
        private final String defaultTargetUrl;

        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
            log.info("Single Authentication successful (JWT Emitter): User {}. Issuing tokens.", authentication.getName());
            String deviceId = request.getHeader("X-Device-Id");
            if (deviceId == null) deviceId = getOrCreateSessionDeviceId(request);

            String accessToken = tokenService.createAccessToken(authentication, deviceId);
            String refreshToken = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshToken = tokenService.createRefreshToken(authentication, deviceId);
            }

            Map<String, Object> tokenResponse = new HashMap<>();
            tokenResponse.put("status", "SUCCESS");
            tokenResponse.put("message", "로그인 성공");
            tokenResponse.put("accessToken", accessToken);
            if (refreshToken != null) tokenResponse.put("refreshToken", refreshToken);
            tokenResponse.put("redirectUrl", determineTargetUrl(request, response, authentication));

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json;charset=UTF-8");
            objectMapper.writeValue(response.getWriter(), tokenResponse);
        }

        private String getOrCreateSessionDeviceId(HttpServletRequest request) {
            HttpSession session = request.getSession(true);
            String deviceId = (String) session.getAttribute("sessionDeviceIdForAuth");
            if (deviceId == null) {
                deviceId = UUID.randomUUID().toString();
                session.setAttribute("sessionDeviceIdForAuth", deviceId);
            }
            return deviceId;
        }
        protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
            // 실제로는 SavedRequest가 있다면 그곳으로, 아니면 defaultTargetUrl
            // SavedRequestAwareAuthenticationSuccessHandler의 로직 참조 가능
            HttpSession session = request.getSession(false);
            if (session != null) {
                org.springframework.security.web.savedrequest.SavedRequest savedRequest = (org.springframework.security.web.savedrequest.SavedRequest) session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
                if (savedRequest != null) {
                    return savedRequest.getRedirectUrl();
                }
            }
            return defaultTargetUrl;
        }
    }
}