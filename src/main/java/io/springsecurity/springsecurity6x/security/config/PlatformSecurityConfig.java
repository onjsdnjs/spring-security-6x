package io.springsecurity.springsecurity6x.security.config;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.impl.IdentityDslRegistry;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PlatformSecurityConfig {

    @Bean
    public PlatformConfig securityPlatform() {

        return new IdentityDslRegistry()
                .global(http -> {
                    http.csrf(AbstractHttpConfigurer::disable);
                    http.authorizeHttpRequests(a -> a.anyRequest().permitAll());
                })

                .form(form -> form
                        .matchers("/login/**")
                        .loginPage("/login")
                        .usernameParameter("user")
                        .passwordParameter("pass")
                        .raw(http -> {
                            http.authorizeHttpRequests(a -> a
                                    .requestMatchers("/public/**").permitAll()
                                    .anyRequest().authenticated()
                            );
                        })
                        .raw(http -> {
                            http.headers(headers -> headers.frameOptions().disable());
                        })
                )
                .session()
                .build();
    }

}
