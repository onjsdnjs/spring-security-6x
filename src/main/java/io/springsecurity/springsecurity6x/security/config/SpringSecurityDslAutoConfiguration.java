package io.springsecurity.springsecurity6x.security.config;

import io.springsecurity.springsecurity6x.security.builder.PlatformSecurityChainBuilder;
import io.springsecurity.springsecurity6x.security.dsl.IdentityDsl;
import io.springsecurity.springsecurity6x.security.dsl.IdentityDslImpl;
import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.dsl.state.session.SessionStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;
import java.util.List;

@Configuration
public class SpringSecurityDslAutoConfiguration {

    @Bean
    public List<SecurityFilterChain> filterChains(ObjectProvider<HttpSecurity> provider, IdentityDsl dsl, SecretKey key,
                                                  AuthContextProperties props) throws Exception {

        return new PlatformSecurityChainBuilder(
                provider,
                new JwtStateConfigurerImpl(key, props),
                new SessionStateConfigurerImpl(props)
        ).buildFrom(dsl.getConfig());
    }
}
