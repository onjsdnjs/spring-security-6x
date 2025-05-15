package io.springsecurity.springsecurity6x.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.IdentityDslRegistry;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.handler.MfaAuthenticationFailureHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaStepBasedSuccessHandler;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.service.ott.EmailOneTimeTokenService;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.HashMap;
import java.util.Map;

@Configuration
@RequiredArgsConstructor // 생성자 주입을 위해 추가
@Slf4j
public class PlatformSecurityConfig {

    private final ApplicationContext applicationContext;
    private final EmailOneTimeTokenService emailOneTimeTokenService; // Spring Security OTP 서비스
    private final TokenService tokenService; // 최종 토큰 발급용 (JWT 사용 시)

    // --- MFA 흐름 제어를 위한 공통 핸들러 빈 등록 (신규 또는 기존 핸들러 수정) ---
    // MfaStepBasedSuccessHandler 와 MfaAuthenticationFailureHandler 는
    // FactorContext를 읽고, 다음 단계로 리다이렉션하거나 최종 토큰을 발급/실패 처리를 담당.
    // 이 핸들러들은 각 2차 인증 필터에 설정됩니다.

    @Bean
    public MfaStepBasedSuccessHandler mfaStepBasedSuccessHandler() {
        // 이 핸들러는 FactorContext를 참조하여 다음 MFA 단계 또는 최종 성공 처리를 결정합니다.
        // 생성자에 TokenService, MfaPolicyProvider 등을 주입받아 사용할 수 있습니다.
        return new MfaStepBasedSuccessHandler(tokenService, applicationContext.getBean(io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider.class), applicationContext.getBean(io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence.class));
    }

    @Bean
    public AuthenticationFailureHandler mfaAuthenticationFailureHandler() {
        // MFA 단계별 실패 또는 최종 실패 처리
        // FactorContext의 시도 횟수 등을 업데이트하고 실패 페이지로 안내
        return new MfaAuthenticationFailureHandler("/mfa/failure", applicationContext.getBean(io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence.class));
    }
    // --- 단일 인증용 기본 성공/실패 핸들러 ---
    private AuthenticationSuccessHandler defaultSingleAuthSuccessHandler() {
        SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
        handler.setDefaultTargetUrl("/"); // 기본 성공 URL
        // 필요시 여기서 TokenService를 사용하여 토큰 발급 로직 추가 가능 (MFA가 아닌 단일 인증 성공 시)
        // handler.setTargetUrlParameter("redirectTo"); // URL 파라미터로 리다이렉션 제어
        return handler;
    }

    private AuthenticationFailureHandler defaultSingleAuthFailureHandler(String failureUrl) {
        return new SimpleUrlAuthenticationFailureHandler(failureUrl);
    }


    @Bean
    public PlatformConfig securityPlatformDsl(IdentityDslRegistry registry,
                                              MfaStepBasedSuccessHandler mfaStepBasedSuccessHandler,
                                              AuthenticationFailureHandler mfaAuthenticationFailureHandler) {
        return registry
                .global(http -> http
                        .csrf(csrf -> csrf
                                .ignoringRequestMatchers(
                                        new AntPathRequestMatcher("/h2-console/**"),
                                        new AntPathRequestMatcher("/api/**") // API는 Stateless JWT 인증을 가정하고 CSRF 무시 (필요에 따라 조정)
                                )
                        )
                        .authorizeHttpRequests(authReq -> authReq
                                .requestMatchers(
                                        // 단일 인증 및 회원가입
                                        "/", "/loginForm", "/loginOtt", "/loginPasskey", "/ott/sent", "/register", "/authMode",
                                        "/api/register", "/api/auth/refresh",
                                        // 단일 OTT/Passkey 처리 경로 (Spring Security 필터가 처리)
                                        "/login/ott", "/login/webauthn", "/webauthn/assertion/options", // 단일 Passkey 옵션
                                        // MFA 흐름 제어용 API 및 페이지
                                        "/mfa/select-factor", "/mfa/verify/ott", "/mfa/verify/passkey", "/mfa/failure",
                                        "/api/mfa/select-factor", // 2차 인증 수단 선택 처리
                                        "/api/mfa/request-ott-code", // MFA OTT 코드 요청
                                        "/api/mfa/assertion/options" // MFA Passkey 옵션 요청
                                ).permitAll()
                                .requestMatchers("/css/**", "/js/**", "/images/**").permitAll() // 정적 리소스
                                .requestMatchers("/api/users").hasRole("USER") // 예시: USER 역할 필요
                                .requestMatchers("/api/admin/**").hasRole("ADMIN") // 예시: ADMIN 역할 필요
                                .anyRequest().authenticated() // 그 외 모든 요청은 인증 필요
                        )
                        .headers(headers -> headers
                                .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable) // H2 콘솔용
                        )
                )
                // --- 단일 인증 흐름 설정 (MFA가 아닌 직접 로그인 시) ---
                .form(form -> form // 단일 Form 로그인
                        .loginPage("/loginForm") // 커스텀 로그인 페이지
                        .loginProcessingUrl("/login") // Spring Security가 처리할 Form 제출 경로 (기본값)
                        .successHandler(defaultSingleAuthSuccessHandler()) // 기본 성공 핸들러
                        .failureHandler(defaultSingleAuthFailureHandler("/loginForm?error"))
                        .permitAll())
                .session(Customizer.withDefaults())

                .ott(ott -> ott
                        .tokenService(emailOneTimeTokenService) // 주입된 OTT 서비스 사용
                        .tokenGeneratingUrl("/ott/generate") // OTT 코드/링크 발송 요청 URL (컨트롤러에서 EmailOTTService.generate() 호출)
                        .loginProcessingUrl("/login/ott")    // OTT 코드/링크 검증 URL (OneTimeTokenAuthenticationFilter가 처리)
                        .successHandler(defaultSingleAuthSuccessHandler())
                        .failureHandler(defaultSingleAuthFailureHandler("/loginOtt?error")))
                .session(Customizer.withDefaults())

                .passkey(passkey -> passkey // 단일 Passkey 로그인
                        .rpId("localhost") // application.yml 또는 여기서 설정
                        .assertionOptionsEndpoint("/webauthn/assertion/options") // Passkey 옵션 요청 URL (컨트롤러에서 WebAuthnServer.generateAssertionOptions() 호출)
                        .loginProcessingUrl("/login/webauthn") // Passkey 검증 URL (WebAuthnAuthenticationFilter가 처리)
                        .successHandler(defaultSingleAuthSuccessHandler())
                        .failureHandler(defaultSingleAuthFailureHandler("/loginPasskey?error")))
                .session(Customizer.withDefaults())

                .mfa(mfa -> mfa
                                // 1차 인증: REST API (ID/PW) 사용
                                .rest(rest -> rest
                                        .loginProcessingUrl("/api/auth/login") // 1차 인증 처리 URL (RestAuthenticationFilter가 처리)
                                        // RestAuthenticationFilter의 successHandler에서 MFA 분기 처리 (FactorContext 생성 및 /mfa/select-factor로 안내)
                                        .successHandler(applicationContext.getBean("mfaCapableRestSuccessHandler", AuthenticationSuccessHandler.class)) // 아래에서 빈으로 정의
                                        .failureHandler(defaultSingleAuthFailureHandler("/loginForm?error")) // 1차 인증 실패 시
                                )
                                // 2차 인증: OTT (MFA의 한 단계로 사용될 때)
                                .ott(ott -> ott
                                        .tokenService(emailOneTimeTokenService)
                                        // 이 loginProcessingUrl은 클라이언트가 MFA 중 OTT를 선택했을 때 폼을 제출할 경로.
                                        // OneTimeTokenAuthenticationFilter가 이 경로를 처리.
                                        .loginProcessingUrl("/login/mfa-ott")
                                        .successHandler(mfaStepBasedSuccessHandler) // MFA 단계 성공 처리
                                        .failureHandler(mfaAuthenticationFailureHandler) // MFA 단계 실패 처리
                                )
                                // 2차 인증: Passkey (MFA의 한 단계로 사용될 때)
                                .passkey(passkey -> passkey
                                        .rpId("localhost")
                                        // 이 loginProcessingUrl은 클라이언트가 MFA 중 Passkey를 선택했을 때 폼을 제출할 경로.
                                        // WebAuthnAuthenticationFilter가 이 경로를 처리.
                                        .loginProcessingUrl("/login/mfa-passkey")
                                        .successHandler(mfaStepBasedSuccessHandler) // MFA 단계 성공 처리
                                        .failureHandler(mfaAuthenticationFailureHandler) // MFA 단계 실패 처리
                                )
                                .order(10) // 다른 단일 인증 흐름보다 우선순위를 낮게 설정 (경로가 겹치지 않도록 주의)
                                .finalSuccessHandler(mfaStepBasedSuccessHandler) // 모든 MFA 단계 완료 후 최종 성공 처리
                        // .policyProvider(...) // 필요시 커스텀 MfaPolicyProvider 설정
                )
                .jwt(Customizer.withDefaults()) // 최종 상태 관리: JWT
                .build();
    }

    // 1차 인증(REST) 성공 후 MFA 분기를 처리하는 SuccessHandler 빈 (신규)
    // RestAuthenticationFilter에 설정됩니다.
    @Bean
    public AuthenticationSuccessHandler mfaCapableRestSuccessHandler(
            ContextPersistence contextPersistence,
            MfaPolicyProvider mfaPolicyProvider,
            TokenService tokenService,
            AuthContextProperties authContextProperties) {

        // 이 핸들러는 RestAuthenticationFilter의 successfulAuthentication 로직과 유사하게 동작
        // 1차 인증 성공 시 MFA 필요 여부 판단 -> FactorContext 생성/저장 -> 클라이언트에 MFA_REQUIRED 및 다음 경로 안내
        // 또는 MFA 불필요 시 토큰 바로 발급
        return (request, response, authentication) -> {
            log.info("MFA Capable REST Success Handler: Primary authentication successful for user: {}", authentication.getName());

            // FactorContext 생성 및 MFA 정책 평가
            FactorContext mfaCtx = new FactorContext(authentication); // 기본 상태로 생성
            // MfaPolicyProvider를 통해 이 사용자가 MFA를 사용해야 하는지, 사용 가능한 Factor는 무엇인지 등을 mfaCtx에 설정
            mfaPolicyProvider.evaluateMfaPolicy(mfaCtx);

            if (mfaCtx.isMfaRequired()) {
                log.info("MFA is required for user: {}. Saving FactorContext and guiding to MFA selection.", authentication.getName());
                contextPersistence.saveContext(mfaCtx, request);

                Map<String, Object> mfaRequiredResponse = new HashMap<>();
                mfaRequiredResponse.put("status", "MFA_REQUIRED");
                mfaRequiredResponse.put("message", "Primary authentication successful. MFA is required.");
                mfaRequiredResponse.put("mfaSessionId", mfaCtx.getMfaSessionId());
                // 클라이언트가 다음으로 이동할 MFA Factor 선택 페이지 URL
                mfaRequiredResponse.put("nextStepUrl", authContextProperties.getMfa().getInitiateUrl()); // 예: "/mfa/select-factor"

                response.setStatus(HttpServletResponse.SC_OK);
                response.setContentType("application/json;charset=UTF-8");
                new ObjectMapper().writeValue(response.getWriter(), mfaRequiredResponse); // ObjectMapper는 TokenService에서 가져오거나 주입
            } else {
                log.info("MFA is not required for user: {}. Issuing tokens directly.", authentication.getName());
                // MFA 불필요, 바로 토큰 발급 (TokenIssuingSuccessHandler 로직과 유사)
                String deviceId = request.getHeader("X-Device-Id"); // form-login.js 에서 전달
                String accessToken = tokenService.createAccessToken(authentication, deviceId);
                String refreshToken = tokenService.properties().isEnableRefreshToken() ? tokenService.createRefreshToken(authentication, deviceId) : null;

                // TokenTransportStrategy를 사용하여 토큰 전송
                tokenService.writeAccessAndRefreshToken(response, accessToken, refreshToken);
            }
        };
    }
}