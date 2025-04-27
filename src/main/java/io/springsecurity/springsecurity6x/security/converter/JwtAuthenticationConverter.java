/*
package io.springsecurity.springsecurity6x.security.converter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.springsecurity.springsecurity6x.security.token.parser.JwtParser;
import io.springsecurity.springsecurity6x.security.token.parser.ParsedJwt;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.List;
import java.util.stream.Collectors;

*/
/**
 * JWT 문자열을 파싱하여 Spring Security Authentication 으로 변환하는 컴포넌트
 *//*

public class JwtAuthenticationConverter implements AuthenticationConverter {

    private final JwtParser parser;

    public JwtAuthenticationConverter(JwtParser parser) {
        this.parser = parser;
    }

    @Override
    public Authentication getAuthentication(String token) {
        ParsedJwt jwt = parser.parse(token);
        String user = jwt.getSubject();
        List<String> roles = jwt.getClaim("roles", List.class);
        var auths = roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        return new UsernamePasswordAuthenticationToken(user, null, auths);
    }

    @Override
    public List<String> getRoles(String token) {
        ParsedJwt jwt = parser.parse(token);
        return jwt.getClaim("roles", List.class);
    }
}
*/
