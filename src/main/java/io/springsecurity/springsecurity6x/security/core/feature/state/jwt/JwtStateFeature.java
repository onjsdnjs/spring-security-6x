package io.springsecurity.springsecurity6x.security.core.feature.state.jwt;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
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
    private JwtStateConfigurer configurer;

    @Override
    public String getId() {
        return "jwt";
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext ctx) throws Exception {

        SecretKey key = ctx.getShared(SecretKey.class);
        AuthContextProperties props = ctx.getShared(AuthContextProperties.class);

        TokenTransportType transportType = props.getTokenTransportType();
        TokenTransportStrategy transport = TokenTransportStrategyFactory.create(transportType);

        JwtStateConfigurer configurer = new JwtStateConfigurer(key, props, transport);
        http.with(configurer, Customizer.withDefaults());
    }
}
