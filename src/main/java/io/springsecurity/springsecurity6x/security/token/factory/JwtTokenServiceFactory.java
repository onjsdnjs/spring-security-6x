package io.springsecurity.springsecurity6x.security.token.factory;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.JwtTokenCreator;
import io.springsecurity.springsecurity6x.security.token.parser.JwtTokenParser;
import io.springsecurity.springsecurity6x.security.token.service.JwtTokenService;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.store.JwtRefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategyFactory;
import io.springsecurity.springsecurity6x.security.token.validator.JwtTokenValidator;

import javax.crypto.SecretKey;

public class JwtTokenServiceFactory {
    public static TokenService createService(PlatformContext ctx) {

        SecretKey key = ctx.getShared(SecretKey.class);
        AuthContextProperties props = ctx.getShared(AuthContextProperties.class);
        TokenTransportStrategy transport = TokenTransportStrategyFactory.create(props);
        JwtTokenParser jwtTokenParser = new JwtTokenParser(key);
        JwtRefreshTokenStore jwtRefreshTokenStore = new JwtRefreshTokenStore(new JwtTokenParser(key), props);

        JwtTokenService tokenService = new JwtTokenService(
                new JwtTokenValidator(jwtTokenParser, jwtRefreshTokenStore, props.getRefreshRotateThreshold()),
                new JwtTokenCreator(key),
                jwtRefreshTokenStore,
                transport,
                props
        );
        transport.setTokenService(tokenService);
        return tokenService;
    }
}
