package io.springsecurity.springsecurity6x.security.token.creator;

import java.util.List;
import java.util.Map;

public interface TokenCreator {
    String createToken(TokenRequest request);
    default TokenBuilder builder() {
        return new TokenBuilder() {
            private final TokenRequest req = new TokenRequest();
            @Override public TokenBuilder tokenType(String t) { req.setTokenType(t); return this; }
            @Override public TokenBuilder username(String u) { req.setUsername(u); return this; }
            @Override public TokenBuilder validity(long v) { req.setValidity(v); return this; }
            @Override public TokenBuilder roles(List<String> r) { req.setRoles(r); return this; }
            @Override public TokenBuilder claims(Map<String,Object> c) { req.setClaims(c); return this; }
            @Override public String build() { return createToken(req); }
        };
    }
    interface TokenBuilder {
        TokenBuilder tokenType(String tokenType);
        TokenBuilder username(String username);
        TokenBuilder validity(long validity);
        TokenBuilder roles(List<String> roles);
        TokenBuilder claims(Map<String,Object> claims);
        String build();
    }
}


