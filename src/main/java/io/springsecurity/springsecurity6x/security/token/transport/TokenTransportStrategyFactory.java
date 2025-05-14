package io.springsecurity.springsecurity6x.security.token.transport;


import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;

public class TokenTransportStrategyFactory {

    public static TokenTransportStrategy create(AuthContextProperties props) {
        return switch (props.getTokenTransportType()) {
            case HEADER -> new HeaderTokenStrategy(props);
            case COOKIE -> new CookieTokenStrategy(props);
            case HEADER_COOKIE -> new HeaderCookieTokenStrategy(props);
        };
    }
}


