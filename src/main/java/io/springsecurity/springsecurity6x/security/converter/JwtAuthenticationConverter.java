package io.springsecurity.springsecurity6x.security.converter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JWT 문자열을 파싱하여 Spring Security Authentication 으로 변환하는 컴포넌트
 */
public class JwtAuthenticationConverter implements AuthenticationConverter {

    private final SecretKey secretKey;

    public JwtAuthenticationConverter(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    /**
     * JWT 액세스 토큰을 파싱해서 Authentication 객체로 반환
     */
    @Override
    public Authentication getAuthentication(String token) {
        Claims claims = parseClaims(token);
        String username = claims.getSubject();
        List<String> roles = claims.get("roles", List.class);
        var authorities = roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        return new UsernamePasswordAuthenticationToken(username, null, authorities);
    }

    /**
     * 리프레시 토큰에서만 역할 목록만 추출할 때 사용
     */
    @Override
    public List<String> getRoles(String token) {
        Claims claims = parseClaims(token);
        return claims.get("roles", List.class);
    }

    private Claims parseClaims(String token) {

        if (token.startsWith("Bearer ")) {
            token = token.substring(7);
        }
        Jws<Claims> jws = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token);
        return jws.getBody();
    }
}
