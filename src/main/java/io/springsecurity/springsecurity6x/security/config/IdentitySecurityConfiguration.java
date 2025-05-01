package io.springsecurity.springsecurity6x.security.config;

import io.springsecurity.springsecurity6x.security.builder.PlatformSecurityChainBuilder;
import io.springsecurity.springsecurity6x.security.dsl.IdentityDsl;
import io.springsecurity.springsecurity6x.security.dsl.IdentityDslImpl;
import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.dsl.state.session.SessionStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;
import java.util.List;


@Configuration
@RequiredArgsConstructor
public class IdentitySecurityConfiguration {

    private final SecretKey key;
    private final AuthContextProperties props;

    @Bean
    public IdentityDsl identityDsl() {
        return new IdentityDslImpl();
    }

    @Bean
    public List<SecurityFilterChain> securityFilterChains(ObjectProvider<HttpSecurity> httpSecurityProvider, IdentityDsl dsl)
            throws Exception {
        IdentityDslImpl identityDsl = (IdentityDslImpl) dsl;
        IdentityConfig config = identityDsl.getConfig();

        PlatformSecurityChainBuilder builder = new PlatformSecurityChainBuilder(httpSecurityProvider,
                new JwtStateConfigurerImpl(key, props),
                new SessionStateConfigurerImpl(props)
        );

        return builder.buildFrom(config);
    }
}