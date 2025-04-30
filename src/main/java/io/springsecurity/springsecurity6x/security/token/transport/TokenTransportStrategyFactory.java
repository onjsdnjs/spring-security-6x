package io.springsecurity.springsecurity6x.security.token.transport;


import io.springsecurity.springsecurity6x.security.enums.TokenTransportType;

public class TokenTransportStrategyFactory {

    public static TokenTransportStrategy create(TokenTransportType type) {
        return switch (type) {
            case HEADER -> new HeaderTokenStrategy();
            case COOKIE -> new CookieTokenStrategy();
            case HEADER_COOKIE -> new HeaderCookieTokenStrategy();
        };
    }
}


