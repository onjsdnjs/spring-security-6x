package io.springsecurity.springsecurity6x.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.bootstrap.TokenServiceConfiguration;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.IdentityDslRegistry;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.exceptionhandling.TokenAuthenticationEntryPoint;
import io.springsecurity.springsecurity6x.security.handler.MfaAuthenticationFailureHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaCapableRestSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaStepBasedSuccessHandler;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.service.ott.EmailOneTimeTokenService;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.utils.WebUtil;
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
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Configuration
@RequiredArgsConstructor
@Import(TokenServiceConfiguration.class) // TokenService 관련 Bean 설정 Import
public class PlatformSecurityConfig {

    private final ApplicationContext applicationContext;
    private final EmailOneTimeTokenService emailOneTimeTokenService;
    private final TokenService tokenService;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final ContextPersistence contextPersistence;
    private final ObjectMapper objectMapper;
    private final AuthContextProperties authContextProperties;
    private final MfaCapableRestSuccessHandler mfaCapableRestSuccessHandler; // Bean 주입
    private final MfaStepBasedSuccessHandler mfaStepBasedSuccessHandler;     // Bean 주입
    private final MfaAuthenticationFailureHandler mfaAuthenticationFailureHandler; // Bean 주입


    // 단일 인증 성공 시 토큰 발급을 위한 SuccessHandler (내부에서만 사용)
    private AuthenticationSuccessHandler defaultSingleAuthSuccessHandler() {
        return (request, response, authentication) -> {
            log.info("Default Single Auth Success Handler: User {} authenticated. Issuing tokens.", authentication.getName());
            String deviceId = request.getHeader("X-Device-Id");
            if (deviceId == null) deviceId = getOrCreateSessionDeviceId(request);

            String accessToken = tokenService.createAccessToken(authentication, deviceId);
            String refreshToken = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshToken = tokenService.createRefreshToken(authentication, deviceId);
            }

            // API 요청(클라이언트가 JSON 기대)이면 JSON 응답, 아니면 페이지 리다이렉션 유도
            // Form 로그인 같은 전통적 방식은 리다이렉션이 자연스러울 수 있음.
            // 하지만 JWT 환경에서는 일관되게 JSON으로 토큰을 내려주고 클라이언트가 처리하는 것도 방법.
            // 여기서는 요청 URI가 /api로 시작하거나 Accept 헤더를 보고 판단.
            if (WebUtil.isApiOrAjaxRequest(request) || request.getRequestURI().startsWith("/api")) {
                Map<String, Object> tokenResponse = new HashMap<>();
                tokenResponse.put("status", "SUCCESS");
                tokenResponse.put("message", "로그인 성공");
                tokenResponse.put("accessToken", accessToken);
                if (refreshToken != null) {
                    tokenResponse.put("refreshToken", refreshToken);
                }
                // 클라이언트가 리다이렉션해야 할 URL (예: 홈) 명시적 전달
                tokenResponse.put("redirectUrl", "/");

                response.setStatus(HttpServletResponse.SC_OK);
                response.setContentType("application/json;charset=UTF-8");
                objectMapper.writeValue(response.getWriter(), tokenResponse);
            } else {
                // Form 기반 단일 로그인 후 JWT를 사용하지만 페이지 리다이렉션을 원하는 경우:
                // 1. 토큰을 쿠키에 심고 리다이렉션 (TokenTransportStrategy의 쿠키 방식 활용)
                //    tokenService.writeAccessAndRefreshToken(response, accessToken, refreshToken); // transport가 쿠키로 설정되어 있어야 함
                //    new SavedRequestAwareAuthenticationSuccessHandler().onAuthenticationSuccess(request, response, authentication);
                // 2. 또는, 이 핸들러에서 바로 SavedRequestAware로 위임하여 세션 방식처럼 동작 (JWT지만 세션도 같이 사용)
                //    (이 경우, JwtAuthorizationFilter 등이 세션보다 우선하여 토큰을 검증해야 함)
                // 여기서는 일관성을 위해 JSON 응답 후 클라이언트가 처리하도록 유도.
                // 만약 전통적인 Form 로그인 후 리다이렉션을 원한다면 successHandler를 SavedRequestAware로 변경.
                // 그러나 JWT 환경에서는 토큰을 내려주는 것이 일반적.
                // 여기서는 예시로 SavedRequestAware를 사용 (단, 이러면 JWT의 stateless 이점이 희석될 수 있음)
                log.warn("Non-API request for single auth success. Using SavedRequestAware redirection for {}. Consider client-side token handling and redirection.", request.getRequestURI());
                SavedRequestAwareAuthenticationSuccessHandler savedRequestRedirect = new SavedRequestAwareAuthenticationSuccessHandler();
                savedRequestRedirect.setDefaultTargetUrl("/"); // 로그인 후 기본 이동 페이지
                savedRequestRedirect.onAuthenticationSuccess(request, response, authentication);
            }
        };
    }

    private String getOrCreateSessionDeviceId(HttpServletRequest request) {
        HttpSession session = request.getSession(true); // 세션이 없으면 생성
        String deviceId = (String) session.getAttribute("sessionDeviceIdForAuth");
        if (deviceId == null) {
            deviceId = UUID.randomUUID().toString();
            session.setAttribute("sessionDeviceIdForAuth", deviceId);
            log.debug("Generated new session-based deviceId: {}", deviceId);
        }
        return deviceId;
    }

    private AuthenticationFailureHandler defaultSingleAuthFailureHandler(String failureUrl) {
        return new SimpleUrlAuthenticationFailureHandler(failureUrl);
    }

    @Bean
    public PlatformConfig securityPlatformDsl(IdentityDslRegistry registry) {

        return registry
                .global(http -> http
                        .csrf(AbstractHttpConfigurer::disable) // API 서버는 상태를 저장하지 않으므로 CSRF는 일반적으로 불필요 또는 다른 방식(헤더 토큰)으로 처리
                        .authorizeHttpRequests(authReq -> authReq
                                .requestMatchers(
                                        // --- 정적 리소스 ---
                                        "/css/**", "/js/**", "/images/**", "/favicon.ico",
                                        // --- 핵심 인증/MFA 페이지 및 API (permitAll) ---
                                        "/", "/authMode",
                                        "/loginForm", "/register", // 회원가입 페이지
                                        "/loginOtt", "/ott/sent", // 단일 OTT 요청/완료 페이지
                                        "/loginPasskey",          // 단일 Passkey 요청 페이지
                                        "/mfa/select-factor", "/mfa/verify/ott", "/mfa/verify/passkey", "/mfa/failure", // MFA UI 페이지
                                        // --- API 엔드포인트 (permitAll 이지만 내부적으로 인증/세션 검증) ---
                                        "/api/register",           // 회원가입 API
                                        "/api/auth/login",         // 1차 인증 API (MFA 시작점)
                                        "/api/auth/refresh",       // 토큰 재발급 API
                                        "/api/ott/generate",       // 단일 OTT 코드/링크 발송 요청 API
                                        "/webauthn/assertion/options", // 단일 Passkey 옵션 요청 API
                                        "/api/mfa/select-factor",    // MFA - 2차 인증 수단 선택 처리 API
                                        "/api/mfa/request-ott-code", // MFA - OTT 코드 요청 API
                                        "/api/mfa/assertion/options" // MFA - Passkey 옵션 요청 API
                                ).permitAll()
                                .requestMatchers("/users", "/api/users").hasRole("USER") // USER 페이지 및 API는 USER 역할 필요
                                .requestMatchers("/admin", "/api/admin/**").hasRole("ADMIN") // ADMIN 페이지 및 API는 ADMIN 역할 필요
                                .anyRequest().authenticated() // 그 외 모든 요청은 인증 필요
                        )
                        .headers(headers -> headers
                                .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable) // H2 콘솔용
                        )
                        .sessionManagement(session -> session // MFA를 위해 세션 사용
                                .sessionCreationPolicy(authContextProperties.isAllowMultipleLogins() ?
                                        org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED :
                                        org.springframework.security.config.http.SessionCreationPolicy.ALWAYS) // 세션 필요시 생성 또는 항상 생성
                                .sessionFixation().migrateSession()
                                .maximumSessions(authContextProperties.isAllowMultipleLogins() ? authContextProperties.getMaxConcurrentLogins() : 1)
                                .expiredUrl("/loginForm?expired")
                        )
                        .exceptionHandling(e -> e
                                .authenticationEntryPoint(new TokenAuthenticationEntryPoint()) // 401 응답 처리
                        )
                        // 로그아웃 설정 (JWT 사용 시 세션 무효화 + 클라이언트 토큰 제거 유도)
                        .logout(logout -> logout
                                .logoutUrl("/api/auth/logout") // JS가 호출할 로그아웃 API 경로
                                .addLogoutHandler(applicationContext.getBean(io.springsecurity.springsecurity6x.security.handler.logout.JwtLogoutHandler.class)) // JWT 토큰 블랙리스트 등 처리
                                .logoutSuccessHandler((request, response, authentication) -> { // 성공 시 JSON 응답
                                    response.setStatus(HttpServletResponse.SC_OK);
                                    response.setContentType("application/json;charset=UTF-8");
                                    objectMapper.writeValue(response.getWriter(), Map.of("message", "로그아웃 되었습니다.", "redirectUrl", "/loginForm"));
                                })
                                .invalidateHttpSession(true) // 세션 무효화
                                .deleteCookies("JSESSIONID", "remember-me") // 관련 쿠키 삭제 (필요시)
                        )
                )
                // --- 단일 인증 흐름 설정 ---
                .form(form -> form
                        .loginPage("/loginForm")
                        .loginProcessingUrl("/login") // UsernamePasswordAuthenticationFilter가 처리
                        .successHandler(defaultSingleAuthSuccessHandler())
                        .failureHandler(defaultSingleAuthFailureHandler("/loginForm?error"))
                        .permitAll() // 로그인 페이지 자체는 모든 사용자 접근 허용
                ).session(Customizer.withDefaults())

                .ott(ott -> ott
                        .tokenService(emailOneTimeTokenService)
                        .tokenGeneratingUrl("/api/ott/generate") // EmailOneTimeTokenService.generate() 호출하는 컨트롤러 경로
                        .loginProcessingUrl("/login/ott")        // OneTimeTokenAuthenticationFilter가 처리
                        .successHandler(defaultSingleAuthSuccessHandler())
                        .failureHandler(defaultSingleAuthFailureHandler("/loginOtt?error"))
                ).session(Customizer.withDefaults())

                .passkey(passkey -> passkey
                        .rpId(applicationContext.getEnvironment().getProperty("spring.security.webauthn.relyingparty.id", "localhost"))
                        .assertionOptionsEndpoint("/api/passkey/assertion/options") // WebAuthnServer.optionsRequest() 호출하는 컨트롤러 경로
                        .loginProcessingUrl("/login/webauthn") // WebAuthnAuthenticationFilter가 처리
                        .successHandler(defaultSingleAuthSuccessHandler())
                        .failureHandler(defaultSingleAuthFailureHandler("/loginPasskey?error"))
                ).session(Customizer.withDefaults())

                // --- MFA 인증 흐름 설정 ---
                .mfa(mfa -> mfa
                        .rest(rest -> rest // 1차 인증 (ID/PW API)
                                .loginProcessingUrl("/api/auth/login") // RestAuthenticationFilter가 처리
                                .successHandler(mfaCapableRestSuccessHandler) // 1차 인증 성공 및 MFA 분기
                                .failureHandler(defaultSingleAuthFailureHandler("/loginForm?error=CREDENTIAL_INVALID")) // 1차 인증 실패
                        )
                        .ott(ott -> ott // 2차 인증 (MFA의 일부로 OTT 사용)
                                .tokenService(emailOneTimeTokenService)
                                // 클라이언트 JS가 OTT 코드와 함께 이 URL로 폼 제출
                                .loginProcessingUrl("/login/mfa-ott") // OneTimeTokenAuthenticationFilter가 처리
                                .successHandler(mfaStepBasedSuccessHandler) // MFA 단계 성공 시 호출
                                .failureHandler(mfaAuthenticationFailureHandler) // MFA 단계 실패 시 호출
                        )
                        .passkey(passkey -> passkey // 2차 인증 (MFA의 일부로 Passkey 사용)
                                .rpId(applicationContext.getEnvironment().getProperty("spring.security.webauthn.relyingparty.id", "localhost"))
                                // 클라이언트 JS가 Passkey Assertion과 함께 이 URL로 폼 제출
                                .loginProcessingUrl("/login/mfa-passkey") // WebAuthnAuthenticationFilter가 처리
                                .successHandler(mfaStepBasedSuccessHandler) // MFA 단계 성공 시 호출
                                .failureHandler(mfaAuthenticationFailureHandler) // MFA 단계 실패 시 호출
                        )
                        .order(10) // 단일 인증보다 낮은 우선순위 (또는 다른 SecurityFilterChain으로 분리)
                        .finalSuccessHandler(mfaStepBasedSuccessHandler) // 모든 MFA 단계 완료 후 최종 성공 처리 (토큰 발급)
                )
                .jwt(Customizer.withDefaults()) // 최종 상태 관리: JWT (토큰 발급 관련 필터 등 적용)
                .build();
    }
}