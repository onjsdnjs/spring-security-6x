package io.springsecurity.springsecurity6x.security.token.factory;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.handler.logout.JwtLogoutHandler;
import io.springsecurity.springsecurity6x.security.handler.logout.JwtLogoutSuccessHandler;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.JwtTokenCreator;
import io.springsecurity.springsecurity6x.security.token.parser.JwtTokenParser;
import io.springsecurity.springsecurity6x.security.token.service.JwtTokenService;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.store.JwtRefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategyFactory;
import io.springsecurity.springsecurity6x.security.token.validator.JwtTokenValidator;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.crypto.SecretKey;

public class JwtTokenServiceFactory {
    public static TokenService createService(PlatformContext ctx) {

        SecretKey key = ctx.getShared(SecretKey.class);
        AuthContextProperties props = ctx.getShared(AuthContextProperties.class);
        TokenTransportStrategy transport = TokenTransportStrategyFactory.create(props.getTokenTransportType());

        return new JwtTokenService(
                new JwtTokenValidator(new JwtTokenParser(key), new JwtRefreshTokenStore(new JwtTokenParser(key), props), props.getRefreshRotateThreshold()),
                new JwtTokenCreator(key),
                new JwtRefreshTokenStore(new JwtTokenParser(key), props),
                transport,
                props
        );
    }

    public static LogoutHandler createLogoutHandler(TokenService service) {
        return new JwtLogoutHandler(service);
    }

    public static LogoutSuccessHandler createLogoutSuccessHandler() {
        return new JwtLogoutSuccessHandler();
    }
}
