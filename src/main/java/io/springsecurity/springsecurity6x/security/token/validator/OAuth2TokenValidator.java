package io.springsecurity.springsecurity6x.security.token.validator;

import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client.OAuth2IntrospectionResponse;
import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client.OAuth2ResourceClient;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class OAuth2TokenValidator implements TokenValidator {

    private final OAuth2ResourceClient resourceClient;

    public OAuth2TokenValidator(OAuth2ResourceClient resourceClient) {
        this.resourceClient = resourceClient;
    }

    @Override
    public boolean validateAccessToken(String token) {
        return resourceClient.validateAccessToken(token);
    }

    @Override
    public boolean validateRefreshToken(String token) {
        return false; // OAuth2 Client Credentials에서는 refresh_token을 사용하지 않음
    }

    @Override
    public void invalidateRefreshToken(String refreshToken) {
        throw new UnsupportedOperationException("OAuth2 Client Credentials flow에서는 refresh token 만료를 지원하지 않습니다.");
    }

    @Override
    public Authentication getAuthentication(String token) {
        OAuth2IntrospectionResponse userInfo = resourceClient.getUserInfo(token);

        if (!userInfo.isActive()) {
            throw new RuntimeException("Token is invalid");
        }

        List<SimpleGrantedAuthority> authorities = Arrays.stream(userInfo.getScope().split(" "))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        return new UsernamePasswordAuthenticationToken(
                userInfo.getUsername(),
                null,
                authorities
        );
    }
}
