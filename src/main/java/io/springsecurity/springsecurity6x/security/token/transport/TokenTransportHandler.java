package io.springsecurity.springsecurity6x.security.token.transport;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface TokenTransportHandler {

    // 요청(Request)에서 AccessToken 추출
    String extractAccessToken(HttpServletRequest request);

    // 요청(Request)에서 RefreshToken 추출
    String extractRefreshToken(HttpServletRequest request);

    // 응답(Response)에 AccessToken 전송
    void sendAccessToken(HttpServletResponse response, String accessToken);

    // 응답(Response)에 RefreshToken 전송
    void sendRefreshToken(HttpServletResponse response, String refreshToken);

    void clearTokens(HttpServletResponse response);
}


