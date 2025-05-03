package io.springsecurity.springsecurity6x.security.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class MySecurityConfig {
/*
    @Bean
    public IdentityRegistryDsl identityDsl() throws Exception {

        return new IdentityRegistryDsl()
                .form(form -> form
                        .loginPage("/login")).useSession()

                .rest(rest -> rest
                        .loginProcessingUrl("/api/login")).useJwt()
                ;
    }*/

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
