package io.springsecurity.springsecurity6x.security.token.validator;

import io.springsecurity.springsecurity6x.security.token.parser.TokenParser;
import org.springframework.security.core.Authentication;

public interface TokenValidator {

    boolean validateAccessToken(String token);

    boolean validateRefreshToken(String token);

    void invalidateRefreshToken(String refreshToken);

    Authentication getAuthentication(String token);

    /**
     * 리프레시 토큰을 갱신(회전)해야 하는지 여부를 결정합니다.
     * 기본적으로는 회전하지 않도록 false를 반환합니다.
     * @param refreshToken 검사할 리프레시 토큰
     * @return 토큰을 회전해야 하면 true, 그렇지 않으면 false
     */
    default boolean shouldRotateRefreshToken(String refreshToken){return false;};

    /**
     * 이 Validator와 관련된 TokenParser를 반환합니다.
     * 구현체는 이 메소드를 통해 적절한 TokenParser 인스턴스를 제공해야 합니다.
     * 기본 구현은 null을 반환하므로, 실제 사용 시에는 구현체에서 재정의하거나,
     * 호출부에서 null 체크가 필요합니다.
     * @return 관련된 TokenParser 인스턴스, 또는 기본적으로 null
     */
    default TokenParser tokenParser(){return null;}
}
