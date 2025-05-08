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

import java.io.IOException;

@Configuration
public class PlatformSecurityConfig {

    @Bean
    public PlatformConfig securityPlatformDsl() {

        return new IdentityDslRegistry()

                .form(form -> form
                        .loginPage("/login")
                        .usernameParameter("user")
                        .passwordParameter("pass")
                        .rawLogin(f -> f.successHandler(
                                (request, response, authentication) ->
                                        System.out.println("request = " + request)))
                        .raw(http -> { http
                                .authorizeHttpRequests(a -> a
                                            .requestMatchers("/api/auth/login").permitAll()
                                            .anyRequest().permitAll()
                                )
                                .headers(headers -> headers
                                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));
                        }))
                .session(session -> Customizer.withDefaults())

                .rest(rest -> rest
                        .loginProcessingUrl("/api/auth/login")
                        .raw(http -> { http
                                .securityMatcher("/api/auth/**")
                                .authorizeHttpRequests(a -> a
                                        .requestMatchers("/api/auth/login").permitAll()
                                )
                                .headers(headers -> headers
                                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));
                        }))
                .jwt(jwt -> Customizer.withDefaults())

                .global(http -> {
                    http.csrf(AbstractHttpConfigurer::disable);
                    http
//                            .securityMatcher("/api/**")
                            .authorizeHttpRequests(authReq -> authReq
                                    .requestMatchers("/api/register").permitAll()
                                    .requestMatchers("/api/**").authenticated()
                                    .anyRequest().permitAll())
                    ;
                })

                .build();
    }
}
