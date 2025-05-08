package io.springsecurity.springsecurity6x.security.config;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.impl.IdentityDslRegistry;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;

@Configuration
public class PlatformSecurityConfig {

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

                .form(form -> form
                        .order(2)
//                        .loginPage("/login")
                        .usernameParameter("user")
                        .passwordParameter("pass")
                        .rawLogin(f -> f.successHandler(
                                (request, response, authentication) ->
                                        System.out.println("request = " + request)))
                        .raw(http -> { http
//                                .authorizeHttpRequests(a -> a
//                                            .requestMatchers("/login").permitAll()
//                                )
                                .headers(headers -> headers
                                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));
                        }))
                .session(session -> Customizer.withDefaults())

                .rest(rest -> rest
                        .order(1)
                        .loginProcessingUrl("/api/auth/login")
                        .raw(http -> { http
                                .securityMatcher("/api/auth/**");
//                                .authorizeHttpRequests(a -> a
//                                        .requestMatchers("/api/auth/login").permitAll()
//                                )
                        }))
                .jwt(jwt -> Customizer.withDefaults())
                .build();
    }
}
