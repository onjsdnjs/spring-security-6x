package io.springsecurity.springsecurity6x.security.config;

import io.springsecurity.springsecurity6x.security.dsl.IdentityDsl;
import io.springsecurity.springsecurity6x.security.dsl.IdentityDslImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MySecurityConfig {

    @Bean
    public IdentityDsl identityDsl(){
        return new IdentityDslImpl()
                .form(form -> form
                        .loginPage("/login")).useJwt()

                .rest(rest -> rest
                        .loginProcessingUrl("/api/login")).useJwt();
    }

}
