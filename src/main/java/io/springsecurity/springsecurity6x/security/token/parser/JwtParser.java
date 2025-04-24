package io.springsecurity.springsecurity6x.security.token.parser;

/**
 * JWT 문자열을 파싱해서 ParsedJwt 를 반환하는 인터페이스.
 * 실제 파싱 구현체만 라이브러리에 종속됩니다.
 */
public interface JwtParser {
    ParsedJwt parse(String token);
}
