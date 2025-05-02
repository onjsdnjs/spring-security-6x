package io.springsecurity.springsecurity6x.security.config;

import io.springsecurity.springsecurity6x.security.dsl.authentication.multi.IdentityDsl;
import io.springsecurity.springsecurity6x.security.dsl.authentication.multi.IdentityDslImpl;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class MySecurityConfig {

    @Bean
    public IdentityDsl identityDsl() throws Exception {
        return new IdentityDslImpl()
                .form(form -> form
                        .loginPage("/login")).useSession().customize(http ->
                {
                    try {
                        http.authorizeHttpRequests(request -> request.anyRequest().authenticated());
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                })

                .rest(rest -> rest
                        .loginProcessingUrl("/api/login")).useJwt().customize(http ->
                {
                    try {
                        http.authorizeHttpRequests(request -> request.anyRequest().authenticated());
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return (web) -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

}
