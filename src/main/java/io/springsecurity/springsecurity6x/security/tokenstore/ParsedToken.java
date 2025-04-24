package io.springsecurity.springsecurity6x.security.tokenstore;

import java.time.Instant;

/**
 * JWT 페이로드의 최소 메타정보(식별자, 만료시간, 클레임 접근)를 제공하는 도메인 추상화
 */
public interface ParsedToken {
    /** JWT ID (jti 클레임) */
    String getId();

    /** 만료 시간 (exp 클레임) */
    Instant getExpiration();

    /** payload 에 담긴 커스텀 클레임 조회 */
    Object getClaim(String name);
}
