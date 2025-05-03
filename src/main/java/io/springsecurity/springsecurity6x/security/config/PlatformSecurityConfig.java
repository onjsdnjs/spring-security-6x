package io.springsecurity.springsecurity6x.security.config;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.impl.IdentityDslRegistry;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PlatformSecurityConfig {

    @Bean
    public PlatformConfig securityPlatform() {

        IdentityDslRegistry security = new IdentityDslRegistry();

        security.form(form -> form
                        .login(f -> {
                            f.loginPage("/login")                          // 로그인 페이지
                                    .loginProcessingUrl("/authenticate")          // 처리 URL
                                    .usernameParameter("username")                // 사용자명 파라미터
                                    .passwordParameter("password")                // 비밀번호 파라미터
                                    .defaultSuccessUrl("/home", true)             // 성공 시 기본 리다이렉트
                                    .failureUrl("/login?error");          // 실패 시 URL
                        })
                )
                .session(); // session 상태 지정

                return security.build();

                // 2) REST 로그인: API 로그인 엔드포인트, JWT 상태
                /*.rest(rest -> rest
                        .matchers("/api/login")
                        .loginProcessingUrl("/api/authenticate")
                )
                .jwt()

                // 3) OTT 인증 단계: 1회용 토큰 발급용 엔드포인트, 세션 상태
                .ott(ott -> ott
                        .matchers("/ott/request", "/ott/validate")
                        .loginProcessingUrl("/ott/login")
                )
                .session()

                // 4) Passkey(WebAuthn) 인증 단계: 리소스 서버 ID, RP 이름, 허용 출처, JWT 상태
                .passkey(pk -> pk
                        .matchers("/webauthn/register", "/webauthn/login")
                        .rpName("ExampleApp")
                        .rpId("example.com")
                        .allowedOrigins("https://example.com")
                )
                .jwt()

                // 5) MFA(다중 인증) 플로우: 폼 → OTT → Passkey 순서, 최종 세션 상태
                .mfa(mfa -> mfa
                        .form(f -> f
                                .matchers("/mfa/form")
                                .loginPage("/mfa/form")
                                .loginProcessingUrl("/mfa/verify-form")
                        )
                        .ott(o -> o
                                .matchers("/mfa/ott")
                                .loginProcessingUrl("/mfa/verify-ott")
                        )
                        .passkey(p -> p
                                .matchers("/mfa/passkey")
                                .rpName("ExampleApp")
                                .rpId("example.com")
                                .allowedOrigins("https://example.com")
                        )
                )
                .session()*/

    }

    /*@Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return (web) -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }*/

}
