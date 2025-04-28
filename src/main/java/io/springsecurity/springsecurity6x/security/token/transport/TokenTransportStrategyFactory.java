package io.springsecurity.springsecurity6x.security.token.transport;


import io.springsecurity.springsecurity6x.security.enums.TokenTransportType;

public class TokenTransportStrategyFactory {

    public static TokenTransportStrategy create(TokenTransportType type) {

        if (type == TokenTransportType.COOKIE) {
            return new CookieTokenStrategy();
        } else {
            return new HeaderTokenStrategy();
        }
    }
}

