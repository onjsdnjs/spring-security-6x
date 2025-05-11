package io.springsecurity.springsecurity6x.security.config;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.IdentityDslRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class PlatformSecurityConfig2 {

    @Bean
    public PlatformConfig securityPlatformDsl() {

        return new IdentityDslRegistry()

                .global(http -> {
                    http.csrf(csrf -> csrf
                            .ignoringRequestMatchers(new AntPathRequestMatcher("/h2-console/**")));
                    http
//                            .securityMatcher("/api/**")
                        .authorizeHttpRequests(authReq -> authReq
                                .requestMatchers("/api/register", "/api/auth/login", "/api/auth/refresh").permitAll()
                                .requestMatchers("/api/**").authenticated()
                                .anyRequest().permitAll())
                        .headers(headers -> headers
                                .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));
                    ;
                })

                .mfa(m -> m
                        .rest(r -> r.loginProcessingUrl("/api/login"))
                        .ott(o -> o.loginProcessingUrl("/api/ott"))
                        .passkey(p -> p.rpName("app"))
                        .order(5)
                        .retryPolicy(rp -> rp.maxAttempts(3).lockoutSec(60))
                        .adaptive(ad -> ad.geolocation(true))
                        .deviceTrust(true)
                        .recoveryFlow(rc -> rc.emailOtpEndpoint("/recover/email")))
                .jwt(jwt -> Customizer.withDefaults())

                .mfa(m -> m
                        .form(f -> f.loginProcessingUrl("/api/login"))
//                        .ott(o -> o.loginProcessingUrl("/api/ott"))
                        .passkey(p -> p.rpName("app"))
                        .order(6)
                        .retryPolicy(rp -> rp.maxAttempts(3).lockoutSec(60))
                        .adaptive(ad -> ad.geolocation(true))
                        .deviceTrust(true)
                        .recoveryFlow(rc -> rc.emailOtpEndpoint("/recover/email")))
                .jwt(jwt -> Customizer.withDefaults())

                .build();
    }
}
