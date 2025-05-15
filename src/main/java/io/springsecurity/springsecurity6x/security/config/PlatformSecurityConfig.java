package io.springsecurity.springsecurity6x.security.config;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.IdentityDslRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class PlatformSecurityConfig {

    @Bean
    public PlatformConfig securityPlatformDsl(IdentityDslRegistry registry) {

        return registry
                .global(http -> {
                    http.csrf(csrf -> csrf
                            .ignoringRequestMatchers(new AntPathRequestMatcher("/h2-console/**")));
                    http
//                            .securityMatcher("/api/**")
                        .authorizeHttpRequests(authReq -> authReq
                                .requestMatchers("/api/register", "/api/auth/login", "/api/auth/refresh", "/api/auth/mfa").permitAll()
                                .requestMatchers("/api/**").authenticated()
                                .anyRequest().permitAll())
                        .headers(headers -> headers
                                .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));
                    ;
                })

                .mfa(m -> m
                        .rest(r -> r
                                .loginProcessingUrl("/api/auth/login")
                                .rawHttp(http -> { http.securityMatcher("/api/auth/mfa");})
                        )
                        .ott(ott -> ott.loginProcessingUrl("/loginOtt"))
                        .passkey(passkey -> passkey.loginProcessingUrl("/loginPasskey"))
                        .order(5))
//                        .defaultRetryPolicy(rp -> rp.maxAttempts(3).lockoutSec(60))
//                        .defaultAdaptivePolicy(ad -> ad.geolocation(true))
//                        .defaultDeviceTrustEnabled(true)
//                        .recoveryFlow(rc -> rc.codeLength(100)))
                .jwt(jwt -> Customizer.withDefaults())


                .build();
    }
}
