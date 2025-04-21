package io.springsecurity.springsecurity6x.jwt.converter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.security.Key;
import java.util.List;
import java.util.stream.Collectors;

public class JwtAuthenticationConverter implements AuthenticationConverter {

    private final Key secretKey;

    public JwtAuthenticationConverter(Key secretKey) {
        this.secretKey = secretKey;
    }

    public UsernamePasswordAuthenticationToken getAuthentication(String token) {
        Claims claims = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody();
        String username = claims.getSubject();
        List<String> roles = (List<String>)claims.get("roles", List.class);
        List<SimpleGrantedAuthority> authorities = roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        return new UsernamePasswordAuthenticationToken(username, token, authorities);
    }

}
