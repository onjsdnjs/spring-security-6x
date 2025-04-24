package io.springsecurity.springsecurity6x.security.tokenstore;

/**
 * Refresh token 문자열을 파싱해서 ParsedToken 으로 반환하는 인터페이스.
 * 특정 JWT 라이브러리에 의존하지 않음.
 */
public interface RefreshTokenParser {
    ParsedToken parse(String token);
}
