package io.springsecurity.springsecurity6x.security.core.feature.state;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import io.springsecurity.springsecurity6x.security.core.issuer.local.JwtIssuer;
import io.springsecurity.springsecurity6x.security.enums.TokenTransportType;
import io.springsecurity.springsecurity6x.security.handler.authentication.AuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategyFactory;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import javax.crypto.SecretKey;

public class JwtStateFeature implements StateFeature {

    private SecretKey key;
    private AuthContextProperties props;
    private TokenTransportStrategy transport;
    private AuthenticationHandlers handlers;
    private JwtIssuer configurer;

    @Override
    public String getId() {
        return "jwt";
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext ctx) throws Exception {
        // 1) PlatformContext 에서 빈 꺼내오기
        SecretKey key = ctx.getShared(SecretKey.class);
        AuthContextProperties props = ctx.getShared(AuthContextProperties.class);

        // 2) 토큰 전송 전략 생성
        TokenTransportType transportType = props.getTokenTransportType();
        TokenTransportStrategy transport = TokenTransportStrategyFactory.create(transportType);

        // 3) JwtConfigurer를 런타임에 생성하여 초기화·설정 수행
        JwtIssuer configurer = new JwtIssuer(key, props, transport);
        http.with(configurer, Customizer.withDefaults());
//        configurer.init(http);
//        configurer.configure(http);
    }
}
