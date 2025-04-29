package io.springsecurity.springsecurity6x.security.token.parser;

import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client.OAuth2ResourceClient;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class OAuth2TokenParser implements TokenParser {

    private final OAuth2ResourceClient resourceClient;

    public OAuth2TokenParser(OAuth2ResourceClient resourceClient) {
        this.resourceClient = resourceClient;
    }

    @Override
    public ParsedJwt parse(String token) {
        var userInfo = resourceClient.getUserInfo(token);

        if (userInfo == null || !userInfo.active()) {
            throw new RuntimeException("Token is inactive or invalid.");
        }

        List<String> roles = (userInfo.scope() != null)
                ? Arrays.stream(userInfo.scope().split(" "))
                .map(String::trim)
                .filter(role -> !role.isEmpty())
                .collect(Collectors.toList())
                : Collections.emptyList();

        Instant expiration = (userInfo.expiresAt() != null)
                ? Instant.ofEpochSecond(userInfo.expiresAt())
                : Instant.now().plusSeconds(3600);  // 예외 대비 기본 만료 1시간 설정 (옵션)

        return new ParsedJwt(
                null,                      // OAuth2 AccessToken에는 jti(id) 없음
                userInfo.username(),     // subject
                expiration,                 // expiration
                roles                       // roles
        );
    }

    @Override
    public boolean isValidAccessToken(String token) {
        var userInfo = resourceClient.getUserInfo(token);
        return userInfo != null && userInfo.active();
    }

    @Override
    public boolean isValidRefreshToken(String token) {
        return false; // client_credentials 흐름은 refresh_token 없음
    }
}
