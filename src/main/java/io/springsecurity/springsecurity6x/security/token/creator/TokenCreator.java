package io.springsecurity.springsecurity6x.security.token.creator;

public interface TokenCreator {
    String createToken(TokenRequest request);
}


