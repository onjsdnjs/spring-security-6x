package io.springsecurity.springsecurity6x.security.config;

import io.springsecurity.springsecurity6x.security.dsl.authentication.multi.IdentityDsl;
import io.springsecurity.springsecurity6x.security.postprocesor.DynamicSecurityRegistrar;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import javax.crypto.SecretKey;

@Configuration
public class SpringSecurityDslAutoConfiguration {

    @Bean
    public static DynamicSecurityRegistrar dynamicSecurityRegistrar(
            IdentityDsl identityDsl,
            ObjectProvider<HttpSecurity> provider,
            SecretKey key,
            AuthContextProperties props) {
        return new DynamicSecurityRegistrar(identityDsl, provider, key, props);
    }
}
