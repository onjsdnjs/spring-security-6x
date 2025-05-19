package io.springsecurity.springsecurity6x.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.asep.autoconfigure.AsepAutoConfiguration;
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
// 또는 클래스 레벨에 @EnableAsep // ASEP 자동 구성 활성화
public class PlatformSecurityConfig {

    private final ApplicationContext applicationContext; // @RequiredArgsConstructor에 의해 주입
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

    /**
     * 플랫폼의 모든 SecurityFilterChain 설정을 담는 PlatformConfig 빈을 생성합니다.
     * 각 HttpSecurity 인스턴스에 대한 IdentityDslRegistry를 생성하여 DSL 설정을 적용합니다.
     *
     * @param http SecurityFilterChain을 생성하기 위한 HttpSecurity 객체 (Spring Boot가 주입)
     * 실제로는 SecurityFilterChain 빈을 여러 개 정의하고 각 빈마다 다른 HttpSecurity를 구성.
     * 여기서는 단일 PlatformConfig 빈이 모든 설정을 포함한다고 가정.
     * 만약 여러 SecurityFilterChain 빈이 필요하다면, 이 메소드는 SecurityFilterChain을 반환해야 함.
     * 현재 IdentityDslRegistry는 PlatformConfig.Builder를 받으므로,
     * 이 메소드는 PlatformConfig를 반환하는 것이 적절해 보임.
     * 그리고 이 PlatformConfig를 사용하여 SecurityConfigurerOrchestrator가
     * 실제 SecurityFilterChain들을 생성하고 등록하는 별도의 @Configuration 클래스가 있을 수 있음.
     *
     * @return 구성된 PlatformConfig 객체
     * @throws Exception 설정 중 발생할 수 있는 예외
     */
    @Bean
    public PlatformConfig platformDslConfig(HttpSecurity http) throws Exception { // HttpSecurity를 직접 주입받음
        log.info("PlatformSecurityConfig: Configuring platformDslConfig with HttpSecurity hash: {}", http.hashCode());

        // 각 SecurityFilterChain (또는 HttpSecurity 인스턴스)에 대한 DSL 설정을 위해
        // IdentityDslRegistry를 해당 HttpSecurity 인스턴스와 함께 생성.
        // 만약 여러 HttpSecurity 인스턴스를 다룬다면, 이 platformDslConfig 빈은
        // 각 HttpSecurity 인스턴스에 대해 IdentityDslRegistry를 사용하여 PlatformConfig.Builder에 Flow를 추가해야 함.
        // 여기서는 단일 HttpSecurity 인스턴스에 대한 설정을 PlatformConfig에 담는다고 가정.
        IdentityDslRegistry<HttpSecurity> registry = new IdentityDslRegistry<>(this.applicationContext, http);

        String rpId = applicationContext.getEnvironment().getProperty("spring.security.webauthn.relyingparty.id", "localhost");

        // ASEP 커스텀 설정 예시 (실제 Resolver/Handler는 사용자 프로젝트에 구현되어야 함)
        // final var customArgResolver = new com.example.asep.custom.ExampleCustomArgumentResolver();
        // final var customRetValHandler = new com.example.asep.custom.ExampleCustomReturnValueHandler();

        return registry
                .global(globalHttp -> { // globalHttp는 HttpSecurity 자체 (SafeHttpCustomizer의 인자)
                    globalHttp
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
                            .exceptionHandling(e -> e.authenticationEntryPoint(new TokenAuthenticationEntryPoint(objectMapper)))
                            .logout(logout -> logout
                                    .logoutUrl("/api/auth/logout")
                                    .addLogoutHandler(applicationContext.getBean("jwtLogoutHandler", LogoutHandler.class))
                                    .logoutSuccessHandler((request, response, authentication) -> {
                                        response.setStatus(HttpServletResponse.SC_OK);
                                        response.setContentType("application/json;charset=UTF-8");
                                        objectMapper.writeValue(response.getWriter(), Map.of("message", "로그아웃 되었습니다.", "redirectUrl", "/loginForm"));
                                    })
                                    .invalidateHttpSession(true) // JWT 사용 시 false일 수 있으나, 기존 코드 유지
                                    .deleteCookies("JSESSIONID") // 쿠키 사용하는 경우
                            );
                    // 글로벌 ASEP 설정 (AsepConfigurer가 처리하므로 여기서는 DSL 호출 불필요.
                    // 만약 플랫폼 최상위에서 ASEP 설정을 하고 싶다면, 별도의 GlobalAsepAttributes 와
                    // IdentityAuthDsl에 .globalAsep(Customizer<GlobalAsepAttributes>) 와 같은 메소드 필요)
                })
                .form(form -> { // form은 FormDslConfigurer 타입의 인스턴스
                    form
                            .loginPage("/loginForm")
                            .loginProcessingUrl("/login")
                            .successHandler(jwtEmittingAndMfaAwareSuccessHandler)
                            .failureHandler(singleAuthFailureHandler("/loginForm?error"))
                            .order(10)
                            // FormLogin DSL에 ASEP 커스텀 설정 적용
                            .asep(asepForm -> { /* FormAsepAttributes 커스터마이징 */
                                // asepForm.exceptionArgumentResolver(customArgResolver);
                                log.debug("PlatformSecurityConfig: Customizing ASEP for FormLogin.");
                            });
                }).session(Customizer.withDefaults())

                .ott(ott -> {
                    ott
                            .tokenService(emailOneTimeTokenService)
                            .tokenGeneratingUrl("/api/ott/generate")
                            .loginProcessingUrl("/login/ott")
                            .successHandler(jwtEmittingAndMfaAwareSuccessHandler)
                            .failureHandler(singleAuthFailureHandler("/loginOtt?error"))
                            .order(20)
                            .asep(asepOtt -> { /* OttAsepAttributes 커스터마이징 */
                                log.debug("PlatformSecurityConfig: Customizing ASEP for OTT.");
                            });
                }).session(Customizer.withDefaults())

                .passkey(passkey -> {
                    passkey
                            .rpId(rpId)
                            .assertionOptionsEndpoint("/api/passkey/assertion/options")
                            .loginProcessingUrl("/login/webauthn")
                            .successHandler(jwtEmittingAndMfaAwareSuccessHandler)
                            .failureHandler(singleAuthFailureHandler("/loginPasskey?error"))
                            .order(30)
                            .asep(asepPasskey -> { /* PasskeyAsepAttributes 커스터마이징 */
                                log.debug("PlatformSecurityConfig: Customizing ASEP for Passkey.");
                            });
                }).session(Customizer.withDefaults())

                .rest(rest -> { // REST DSL 추가 (제공된 파일 목록에는 없었으나, 일반적으로 사용되므로 추가)
                    rest
                            .loginProcessingUrl("/api/v2/auth/login") // 예시 URL
                            .successHandler(jwtEmittingAndMfaAwareSuccessHandler)
                            .failureHandler(singleAuthFailureHandler("/api/v2/auth/login?error")) // REST는 JSON 오류가 더 적합
                            .order(40)
                            .asep(asepRest -> { /* RestAsepAttributes 커스터마이징 */
                                log.debug("PlatformSecurityConfig: Customizing ASEP for REST.");
                            });
                }).session(Customizer.withDefaults()) // REST는 보통 STATELESS

                .mfa(mfa -> {
                    // MFA 전체 흐름에 대한 ASEP 설정
                    mfa.asep(asepMfaGlobal -> { /* MfaAsepAttributes 커스터마이징 */
                        log.debug("PlatformSecurityConfig: Customizing global ASEP for MFA flow.");
                    });

                    mfa
                            .primaryAuthentication(primaryAuth -> primaryAuth // 1차 인증으로 REST 사용 예시
                                    .restLogin(rest -> rest
                                            .loginProcessingUrl("/api/auth/login") // MFA 내 1차 REST 인증 URL
                                            .successHandler(mfaCapableRestSuccessHandler)
                                            // MFA 내 1차 REST 인증에 대한 ASEP 설정 (RestDslConfigurer의 asep 호출)
                                            .asep(asepMfaPrimaryRest -> {
                                                log.debug("PlatformSecurityConfig: Customizing ASEP for MFA Primary REST.");
                                            })
                                    )
                            )
                            .ott(ottFactor -> {
                                ottFactor.tokenService(emailOneTimeTokenService)
                                        .loginProcessingUrl("/login/mfa-ott") // MFA 내 OTT Factor 처리 URL
                                        .successHandler(mfaStepBasedSuccessHandler)
                                        .failureHandler(mfaAuthenticationFailureHandler)
                                        // MFA 내 OTT Factor에 ASEP 설정 적용
                                        .asep(asepMfaOtt -> {
                                            log.debug("PlatformSecurityConfig: Customizing ASEP for MFA OTT Factor.");
                                        });
                            })
                            .passkey(passkeyFactor -> {
                                passkeyFactor.rpId(rpId)
                                        .loginProcessingUrl("/login/mfa-passkey") // MFA 내 Passkey Factor 처리 URL
                                        .successHandler(mfaStepBasedSuccessHandler)
                                        .failureHandler(mfaAuthenticationFailureHandler)
                                        // MFA 내 Passkey Factor에 ASEP 설정 적용
                                        .asep(asepMfaPasskey -> {
                                            log.debug("PlatformSecurityConfig: Customizing ASEP for MFA Passkey Factor.");
                                        });
                            })
                            .finalSuccessHandler(mfaStepBasedSuccessHandler)
                            .policyProvider(applicationContext.getBean(MfaPolicyProvider.class))
                            .mfaFailureHandler(mfaAuthenticationFailureHandler)
                            .order(5); // MFA 플로우 자체의 순서
                })
                .jwt(Customizer.withDefaults()) // jwt는 JwtStateConfigurer를 적용
                // .jwt(jwt -> jwt.stateAsep(asepJwtState -> { /* JWT 상태 관리 관련 예외 ASEP */ })) // 만약 StateFeature도 ASEP를 갖는다면
                .build();
    }
}