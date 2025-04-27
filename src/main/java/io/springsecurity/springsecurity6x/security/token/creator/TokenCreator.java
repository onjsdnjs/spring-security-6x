package io.springsecurity.springsecurity6x.security.token.creator;

import java.util.List;
import java.util.Map;

public interface TokenCreator {

    TokenBuilder builder();

    interface TokenBuilder {
        TokenBuilder tokenType(String tokenType);  // ⭐ 추가
        TokenBuilder username(String username);
        TokenBuilder validity(long validityMillis);
        TokenBuilder roles(List<String> roles);
        TokenBuilder claims(Map<String, Object> claims);
        String build();
    }
}


