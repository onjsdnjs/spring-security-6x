package io.springsecurity.springsecurity6x.security.token.creator;

public class ExternalJwtCreator implements TokenCreator {
    @Override
    public String createToken(TokenRequest req) {
        if ("refresh".equals(req.getTokenType())) {
            throw new UnsupportedOperationException("외부 refreshToken 직접 생성 불가");
        }
        return "external_token_" + System.currentTimeMillis();
    }
}


