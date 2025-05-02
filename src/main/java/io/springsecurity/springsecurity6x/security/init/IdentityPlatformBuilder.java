package io.springsecurity.springsecurity6x.security.init;

import io.springsecurity.springsecurity6x.security.builder.PlatformSecurityChainBuilder;
import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.dsl.state.session.SessionStateConfigurerImpl;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

/**
 * Identity DSL 등록 정보를 바탕으로 인증 플랫폼을 조립하는 빌더 클래스.
 */
public class IdentityPlatformBuilder {

    private final IdentityDslRegistry registry;
    private final ObjectProvider<HttpSecurity> httpSecurityProvider;
    private final JwtStateConfigurerImpl jwtConfigurer;
    private final SessionStateConfigurerImpl sessionConfigurer;

    public IdentityPlatformBuilder(
            IdentityDslRegistry registry,
            ObjectProvider<HttpSecurity> httpSecurityProvider,
            JwtStateConfigurerImpl jwtConfigurer,
            SessionStateConfigurerImpl sessionConfigurer) {
        this.registry = registry;
        this.httpSecurityProvider = httpSecurityProvider;
        this.jwtConfigurer = jwtConfigurer;
        this.sessionConfigurer = sessionConfigurer;
    }

    public IdentityPlatform build() throws Exception {
        IdentityConfig config = registry.config();

        // 1단계: DSL 로부터 수집된 설정을 바탕으로 필터 전략 구성
        IdentityConfigurerBinder binder = new IdentityConfigurerBinder(config);
        binder.bind();

        // 2단계: PlatformSecurityChainBuilder 로 필터 체인 생성
        PlatformSecurityChainBuilder chainBuilder = new PlatformSecurityChainBuilder(
                httpSecurityProvider, jwtConfigurer, sessionConfigurer);
        List<SecurityFilterChain> chains = chainBuilder.buildChains(config);

        return new IdentityPlatform(chains);
    }
}
