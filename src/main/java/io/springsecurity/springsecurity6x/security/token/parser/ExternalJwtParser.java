package io.springsecurity.springsecurity6x.security.token.parser;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public class ExternalJwtParser implements JwtParser {

    @Override
    public ParsedJwt parse(String token) {
        // 주의: 외부 JWT는 이미 ResourceServer가 서명 검증 완료한 상태임
        Jwt jwt = ((JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication()).getToken();

        return new ParsedJwt(
                jwt.getId(),
                jwt.getSubject(),
                jwt.getExpiresAt(),
                jwt.getClaimAsStringList("roles")  // OpenID Connect 표준 확장 claim
        );
    }

    @Override
    public boolean isValidAccessToken(String token) {
        return true; // ResourceServer가 검증했으므로 항상 true
    }

    @Override
    public boolean isValidRefreshToken(String token) {
        return false; // Authorization Server가 Refresh Token 직접 관리하므로 사용 안 함
    }
}

