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
    public PlatformConfig securityPlatform() {

        return new IdentityDslRegistry()
                .global(http -> {
                        http.csrf(AbstractHttpConfigurer::disable);
                        http
//                            .securityMatcher("/api/**")
                            .authorizeHttpRequests(authReq -> authReq
                            .requestMatchers("/api/register").permitAll()
                            .requestMatchers("/api/**").authenticated()
                            .anyRequest().permitAll());
                })

                .form(form -> form
                        .loginPage("/login")
                        .usernameParameter("user")
                        .passwordParameter("pass")
                        .rawLogin(f -> f.successHandler(new AuthenticationSuccessHandler() {
                            @Override
                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                System.out.println("request = " + request);
                            }
                        }))
                        .raw(http -> {
                            http
//                                .authorizeHttpRequests(a -> a
//                                            .requestMatchers("/public/**").permitAll()
//                                            .anyRequest().authenticated()
//                                )
                                .headers(headers -> headers
                                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));
                        }))
                .jwt()
                .form(form -> Customizer.withDefaults()).session()
                .build();
    }
}
