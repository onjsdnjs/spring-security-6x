package io.springsecurity.springsecurity6x.security.token.parser;

import java.time.Instant;

public interface ParsedJwt {
    String getId();
    String getSubject();
    Instant getExpiration();
    <T> T getClaim(String name, Class<T> type);
}
