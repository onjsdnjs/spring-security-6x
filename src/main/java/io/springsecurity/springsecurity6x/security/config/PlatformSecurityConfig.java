package io.springsecurity.springsecurity6x.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.IdentityDslRegistry;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.exceptionhandling.TokenAuthenticationEntryPoint;
import io.springsecurity.springsecurity6x.security.handler.JwtEmittingAndMfaAwareSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaAuthenticationFailureHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaCapableRestSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaStepBasedSuccessHandler;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
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
    private final AuthResponseWriter authResponseWriter;
    private final EmailOneTimeTokenService emailOneTimeTokenService;
    private final MfaCapableRestSuccessHandler mfaCapableRestSuccessHandler;
    private final MfaStepBasedSuccessHandler mfaStepBasedSuccessHandler;
    private final MfaAuthenticationFailureHandler mfaAuthenticationFailureHandler;
    private final JwtEmittingAndMfaAwareSuccessHandler jwtEmittingAndMfaAwareSuccessHandler; // 최종 성공 및 단일 인증 성공 시 사용


    // 단일 인증 실패 시 기본 핸들러 (페이지 리다이렉트)
    private AuthenticationFailureHandler singleAuthFailureHandler(String failureUrl) {
        return new SimpleUrlAuthenticationFailureHandler(failureUrl);
    }

    @Bean
    public PlatformConfig platformDslConfig(IdentityDslRegistry<HttpSecurity> registry) throws Exception {
        log.info("Configuring Platform Security DSL...");

        String rpId = applicationContext.getEnvironment().getProperty("spring.security.webauthn.relyingparty.id", "localhost");

        // 공통 HTTP 설정 (이전과 유사)
        SafeHttpCustomizer<HttpSecurity> globalHttpCustomizer = http -> {
            try {
                http
                        .csrf(AbstractHttpConfigurer::disable)
                        .authorizeHttpRequests(authReq -> authReq
                                .requestMatchers( // 기존 permitAll 경로 유지
                                        "/css/**", "/js/**", "/images/**", "/favicon.ico",
                                        "/", "/authMode",
                                        "/loginForm", "/register",
                                        "/loginOtt", "/ott/sent", // 단일 OTT 관련 페이지
                                        "/loginPasskey",           // 단일 Passkey 관련 페이지
                                        "/mfa/select-factor", "/mfa/challenge/ott", "/mfa/challenge/passkey", "/mfa/failure", // MFA UI 페이지
                                        "/api/register",
                                        "/api/auth/login", "/api/auth/refresh",         // 1차 인증 및 토큰 API
                                        "/api/ott/generate",                             // 단일 OTT 코드 생성 API
                                        "/webauthn/registration/options", "/webauthn/registration/verify", // 단일 Passkey 등록 API (Spring 기본)
                                        "/webauthn/assertion/options", "/webauthn/assertion/verify",       // 단일 Passkey 검증 API (Spring 기본, 또는 우리가 /login/webauthn 사용)
                                        "/api/mfa/select-factor", "/api/mfa/request-ott-code", "/api/mfa/assertion/options" // MFA 제어 API
                                ).permitAll()
                                .requestMatchers("/users", "/api/users").hasRole("USER")
                                .requestMatchers("/admin", "/api/admin/**").hasRole("ADMIN")
                                .anyRequest().authenticated()
                        )
                        .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                        .sessionManagement(session -> session // JWT 사용 시 Stateless, 세션 사용 시 IF_REQUIRED 등
                                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // JWT 사용 가정
                                // .sessionCreationPolicy(authContextProperties.isAllowMultipleLogins() ?
                                // SessionCreationPolicy.IF_REQUIRED : SessionCreationPolicy.ALWAYS)
                                // .maximumSessions(authContextProperties.isAllowMultipleLogins() ? authContextProperties.getMaxConcurrentLogins() : 1)
                                // .expiredUrl("/loginForm?expired")
                        )
                        .exceptionHandling(e -> e
                                        .authenticationEntryPoint(new TokenAuthenticationEntryPoint(objectMapper))
                                // .accessDeniedHandler(...) // 필요시 AccessDeniedHandler 설정
                        )
                        .logout(logout -> logout
                                .logoutUrl("/api/auth/logout") // JWT 로그아웃 URL
                                .addLogoutHandler(applicationContext.getBean("jwtLogoutHandler", LogoutHandler.class))
                                .logoutSuccessHandler((request, response, authentication) -> {
                                    response.setStatus(HttpServletResponse.SC_OK);
                                    response.setContentType("application/json;charset=UTF-8");
                                    objectMapper.writeValue(response.getWriter(), Map.of("message", "로그아웃 되었습니다.", "redirectUrl", "/loginForm"));
                                })
                                .invalidateHttpSession(false) // JWT 사용 시 세션 무효화 불필요
                                .clearAuthentication(true)
                        );
            } catch (Exception e) {
                throw new RuntimeException("Failed to apply global HttpSecurity customizer", e);
            }
        };


        return registry
                .global(globalHttpCustomizer) // 전역 HttpSecurity 설정 적용

                // --- 단일 인증 방식들 (MFA와 별개로 동작 가능) ---
                .form(form -> form
                        .loginPage("/loginForm")
                        .loginProcessingUrl("/login") // Spring Security의 UsernamePasswordAuthenticationFilter가 처리
                        .successHandler(jwtEmittingAndMfaAwareSuccessHandler) // 성공 시 MFA 필요 여부 판단 또는 JWT 발급
                        .failureHandler(singleAuthFailureHandler("/loginForm?error"))
                        .permitAll()
                        .order(100) // 다른 인증 방식과의 순서
                ).jwt(Customizer.withDefaults()) // Form 로그인 후 JWT 토큰 사용

                .ott(ott -> ott // 단일 OTT 로그인 설정
                        .tokenService(emailOneTimeTokenService) // 플랫폼의 EmailOneTimeTokenService 사용
                        .tokenGeneratingUrl("/api/ott/generate") // OTT 코드 생성 요청 API (LoginController 또는 MfaApiController에서 EmailOneTimeTokenService.generate() 호출)
                        .loginProcessingUrl("/login/ott") // OTT 코드 제출 및 검증 URL (Spring Security의 AuthenticationFilter가 처리)
                        .successHandler(jwtEmittingAndMfaAwareSuccessHandler) // 성공 시 MFA 필요 여부 판단 또는 JWT 발급
                        .failureHandler(singleAuthFailureHandler("/loginOtt?error_ott"))
                        .order(110)
                ).jwt(Customizer.withDefaults()) // 단일 OTT 로그인 후 JWT 토큰 사용

                .passkey(passkey -> passkey // 단일 Passkey 로그인 설정
                        .rpId(rpId)
                        .rpName("Spring Security 6x IDP")
                        // Assertion Options 요청은 Spring Security 기본 엔드포인트(/webauthn/assertion/options) 사용 또는 커스텀 API
                        .assertionOptionsEndpoint("/webauthn/assertion/options")
                        // Assertion 검증은 Spring Security 기본 엔드포인트(/webauthn/assertion/verify) 또는 커스텀 URL
                        .loginProcessingUrl("/login/webauthn") // Passkey Assertion 제출 및 검증 (Spring Security의 WebAuthnAuthenticationFilter가 처리)
                        .successHandler(jwtEmittingAndMfaAwareSuccessHandler) // 성공 시 MFA 필요 여부 판단 또는 JWT 발급
                        .failureHandler(singleAuthFailureHandler("/loginPasskey?error_passkey"))
                        .order(120)
                ).jwt(Customizer.withDefaults()) // 단일 Passkey 로그인 후 JWT 토큰 사용

                // --- MFA 플로우 설정 ---
                .mfa(mfa -> mfa
                        // 1차 인증: REST API 방식 사용
                        .primaryAuthentication(primaryAuth -> primaryAuth
                                .restLogin(rest -> rest
                                        .loginProcessingUrl("/api/auth/login") // 1차 인증 API 경로
                                        .successHandler(mfaCapableRestSuccessHandler) // 1차 인증 성공 후 MFA 정책 평가 및 FactorContext 생성
                                        .failureHandler(mfaAuthenticationFailureHandler) // 1차 인증 실패 또는 MFA 전역 실패 시
                                )
                        )
                        // 2차 인증 요소: OTT
                        .ott(ottFactor -> ottFactor
                                .tokenService(emailOneTimeTokenService) // Spring Security OneTimeTokenService 사용
                                // 이 URL은 MfaStepFilterWrapper가 감지하여, Spring Security의 AuthenticationFilter(OTT용)로 위임됨.
                                // 해당 필터는 주입된 EmailOneTimeTokenService를 사용하여 토큰을 검증.
                                .loginProcessingUrl("/login/mfa-ott")
                                .successHandler(mfaStepBasedSuccessHandler) // OTT Factor 성공 시 다음 단계 또는 최종 완료 처리
                                .failureHandler(mfaAuthenticationFailureHandler) // OTT Factor 실패 시
                        )
                        // 2차 인증 요소: Passkey
                        .passkey(passkeyFactor -> passkeyFactor
                                .rpId(rpId)
                                .rpName("Spring Security 6x IDP MFA")
                                // Passkey Assertion Options 요청은 클라이언트 JS가 /api/mfa/assertion/options API를 호출하도록 함.
                                .assertionOptionsEndpoint("/api/mfa/assertion/options")
                                // 이 URL은 MfaStepFilterWrapper가 감지하여, Spring Security의 WebAuthnAuthenticationFilter로 위임됨.
                                .loginProcessingUrl("/login/mfa-passkey")
                                .successHandler(mfaStepBasedSuccessHandler) // Passkey Factor 성공 시 다음 단계 또는 최종 완료 처리
                                .failureHandler(mfaAuthenticationFailureHandler) // Passkey Factor 실패 시
                        )
                        // MFA 플로우 전반에 대한 설정
                        .finalSuccessHandler(jwtEmittingAndMfaAwareSuccessHandler) // 모든 MFA Factor 완료 후 최종 JWT 발급
                        .policyProvider(applicationContext.getBean(MfaPolicyProvider.class))
                        .mfaFailureHandler(mfaAuthenticationFailureHandler) // MFA 플로우의 전역적 실패 처리
                        .order(20) // 다른 인증 플로우(단일 Form, OTT 등)보다 우선순위 높게 설정 (선택적)
                ).jwt(Customizer.withDefaults()) // MFA 플로우 완료 후 JWT 토큰 사용

                .build();
    }

    // 이하는 PlatformBootstrap 및 SecurityPlatformConfiguration에서
    // HttpSecurity 객체와 각종 Feature/Adapter를 사용하여 SecurityFilterChain을 동적으로 생성하고 등록하는 로직.
    // AbstractAuthenticationAdapter의 apply 메소드 내부에서 각 인증 방식에 맞는
    // Spring Security Configurer (예: http.formLogin(), http.oneTimeTokenLogin(), http.webAuthnLogin())가 호출됨.

    // MfaAuthenticationAdapter의 apply 메소드에서는 MFA 공통 필터(MfaContinuationFilter, MfaStepFilterWrapper)를 등록하고,
    // 그 후 각 2차 인증 요소(OTT, Passkey)에 대한 설정은 해당 요소의 AuthenticationAdapter (OttAuthenticationAdapter, PasskeyAuthenticationAdapter)의
    // apply 메소드가 호출되어 처리됨.

    // FeatureRegistry는 각 인증 방식(form, ott, passkey, mfa 등)의 ID와 해당 AuthenticationAdapter 구현체를 매핑.
    // 또한, MfaStepFilterWrapper가 각 MFA Factor의 loginProcessingUrl 요청을 실제 처리할
    // 스프링 시큐리티 표준 필터(AuthenticationFilter, WebAuthnAuthenticationFilter)로 위임할 수 있도록
    // 이 표준 필터들의 인스턴스를 FeatureRegistry에 등록해주는 메커니즘이 필요.
    // (이는 SecurityFilterChainRegistrar가 SecurityFilterChain 빌드 시점에 수행 가능)
}