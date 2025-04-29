package io.springsecurity.springsecurity6x.security.token.transport;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

import static io.springsecurity.springsecurity6x.security.token.service.TokenService.*;

public class HeaderTokenStrategy implements TokenTransportStrategy {

    private TokenService tokenService;

    @Override
    public void setTokenService(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public String resolveAccessToken(HttpServletRequest request) {
        String authHeader = request.getHeader(ACCESS_TOKEN_HEADER);
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            return authHeader.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        return request.getHeader(REFRESH_TOKEN_HEADER);
    }

    @Override
    public void writeAccessToken(HttpServletResponse response, String accessToken) {
        writeTokens(response, accessToken, null, tokenService.properties().getAccessTokenValidity());
    }

    @Override
    public void writeRefreshToken(HttpServletResponse response, String refreshToken) {
        writeTokens(response, null, refreshToken, tokenService.properties().getRefreshTokenValidity());
    }

    @Override
    public void writeAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken){
        writeTokens(response, accessToken, refreshToken, tokenService.properties().getAccessTokenValidity());
    }

    @Override
    public void clearTokens(HttpServletResponse response) {
        writeTokens(response, null, null, 0);
    }

    private void writeTokens(HttpServletResponse response, String accessToken, String refreshToken, long expiresIn) {
        try {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json;charset=UTF-8");

            TokenResponse body = new TokenResponse(
                    accessToken,
                    "Bearer",
                    expiresIn,
                    refreshToken
            );
            new ObjectMapper().writeValue(response.getWriter(), body);
        } catch (IOException e) {
            throw new RuntimeException("토큰 JSON 응답 실패", e);
        }
    }
}





