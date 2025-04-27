package io.springsecurity.springsecurity6x.security.token.creator;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * 외부 인가서버(OAuth2 Authorization Server) 기반 액세스 토큰 생성기.
 * refreshToken은 외부 서버가 발급하므로, 직접 생성은 하지 않는다.
 */
public class ExternalJwtCreator implements TokenCreator {

    @Override
    public TokenBuilder builder() {
        return new ExternalJwtTokenBuilder();
    }

    private static class ExternalJwtTokenBuilder implements TokenBuilder {

        private String username;
        private long validityMillis;
        private List<String> roles = Collections.emptyList();
        private Map<String, Object> claims = Collections.emptyMap();
        private String tokenType = "access";  // 기본 access

        @Override
        public TokenBuilder tokenType(String tokenType) {
            this.tokenType = tokenType;
            return this;
        }

        @Override
        public TokenBuilder username(String username) {
            this.username = username;
            return this;
        }

        @Override
        public TokenBuilder validity(long validityMillis) {
            this.validityMillis = validityMillis;
            return this;
        }

        @Override
        public TokenBuilder roles(List<String> roles) {
            this.roles = roles != null ? roles : Collections.emptyList();
            return this;
        }

        @Override
        public TokenBuilder claims(Map<String, Object> claims) {
            this.claims = claims != null ? claims : Collections.emptyMap();
            return this;
        }

        @Override
        public String build() {
            if ("refresh".equals(tokenType)) {
                // 외부 인가서버에서는 refreshToken을 직접 생성하지 않는다.
                throw new UnsupportedOperationException("외부 인가서버에서는 refreshToken을 직접 생성할 수 없습니다.");
            }
            // 외부 토큰은 직접 서명하거나 생성하지 않기 때문에 여기서는 단순히 모킹한다.
            return "external_access_token_" + System.currentTimeMillis();
        }
    }
}


