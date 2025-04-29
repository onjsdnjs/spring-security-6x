package io.springsecurity.springsecurity6x.security.token.store;

/**
 * OAuth2 Client Credentials Flow에서는 refresh token을 사용하지 않기 때문에,
 * RefreshTokenStore 인터페이스를 구현하되 모든 메서드는 비활성화 처리한다.
 */
public class OAuth2RefreshTokenStore implements RefreshTokenStore {

    @Override
    public void store(String refreshToken, String username) {
        throw new UnsupportedOperationException("OAuth2 Client Credentials Flow에서는 refresh token 저장을 지원하지 않습니다.");
    }

    @Override
    public String getUsername(String refreshToken) {
        // OAuth2 Client Credentials Flow에서는 refresh token이 존재하지 않음
        return null;
    }

    @Override
    public void remove(String refreshToken) {
        throw new UnsupportedOperationException("OAuth2 Client Credentials Flow에서는 refresh token 삭제를 지원하지 않습니다.");
    }
}

