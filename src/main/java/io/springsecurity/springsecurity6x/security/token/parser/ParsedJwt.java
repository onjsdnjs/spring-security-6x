package io.springsecurity.springsecurity6x.security.token.parser;

import java.time.Instant;

/**
 * JWT 페이로드의 최소 메타정보를 추상화한 인터페이스.
 * 라이브러리 종속을 제거하기 위해 Claims 대신 이 인터페이스만 참조합니다.
 */
public interface ParsedJwt {
    /** JTI 클레임 */
    String getId();
    /** Subject(sub) 클레임 */
    String getSubject();
    /** 만료시각(exp) 클레임 */
    Instant getExpiration();
    /** 커스텀 클레임 조회 */
    <T> T getClaim(String name, Class<T> type);
}
