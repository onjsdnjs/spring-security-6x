package io.springsecurity.springsecurity6x.security.token.service;

import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.Map;
import java.util.function.Consumer;


public interface TokenService {

    String ACCESS_TOKEN = "accessToken";
    String REFRESH_TOKEN = "refreshToken";
    String ACCESS_TOKEN_HEADER  = "Authorization";
    String REFRESH_TOKEN_HEADER = "X-Refresh-Token";
    String BEARER_PREFIX        = "Bearer ";

    String createAccessToken(Authentication authentication);

    String createRefreshToken(Authentication authentication);

    /** 리프레시 토큰 유효성 검증 */
    boolean validateAccessToken(String refreshToken);

    /** 리프레시 토큰 유효성 검증 */
    boolean validateRefreshToken(String refreshToken);

    /** 리프레시 토큰으로부터 Authentication 획득 */
    Authentication getAuthentication(String refreshToken);

    /** 토큰 리프레시 실행 후 결과 반환 */
    RefreshResult refresh(String refreshToken);

    record RefreshResult(String accessToken, String refreshToken) {}


}

