package io.springsecurity.springsecurity6x.security.token.creator;

import io.springsecurity.springsecurity6x.security.enums.TokenType;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;


public class AccessTokenGenerationStrategy implements TokenGenerationStrategy {

    private final TokenCreator creator;
    private final long validity;

    public AccessTokenGenerationStrategy(TokenCreator creator, AuthContextProperties props) {
        this.creator = creator;
        this.validity = props.getAccessTokenValidity();
    }

    @Override
    public TokenType getType() {
        return TokenType.ACCESS;
    }

    @Override
    public String generate(Authentication auth) {
        var roles = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        var req = TokenRequest.builder()
                .tokenType(getType().name().toLowerCase())
                .username(auth.getName())
                .roles(roles)
                .validity(validity)
                .build();

        return creator.createToken(req);
    }
}

