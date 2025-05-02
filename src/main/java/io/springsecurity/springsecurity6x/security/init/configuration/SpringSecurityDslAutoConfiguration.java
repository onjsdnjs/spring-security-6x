package io.springsecurity.springsecurity6x.security.init.configuration;

import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.dsl.state.session.SessionStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.init.DynamicSecurityRegistrar;
import io.springsecurity.springsecurity6x.security.init.IdentityDslRegistry;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import javax.crypto.SecretKey;

/**
 * Identity DSL 플랫폼 자동 설정 클래스.
 * DSL 설정 기반의 SecurityFilterChain 등록을 자동으로 활성화한다.
 */
@Configuration
public class SpringSecurityDslAutoConfiguration {

    @Bean
    public static DynamicSecurityRegistrar dynamicSecurityRegistrar(
            IdentityDslRegistry identityDslRegistry,
            ObjectProvider<HttpSecurity> httpSecurityProvider,
            SecretKey secretKey,
            AuthContextProperties props) {

        JwtStateConfigurerImpl jwtConfigurer = new JwtStateConfigurerImpl(secretKey, props);
        SessionStateConfigurerImpl sessionConfigurer = new SessionStateConfigurerImpl(props);

        return new DynamicSecurityRegistrar(
                identityDslRegistry,
                httpSecurityProvider,
                jwtConfigurer,
                sessionConfigurer
        );
    }
}
