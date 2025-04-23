package io.springsecurity.springsecurity6x.security.converter;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.List;

public class SpringAuthenticationConverter implements AuthenticationConverter {

    private final JwtDecoder jwtDecoder;

    public SpringAuthenticationConverter(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    public UsernamePasswordAuthenticationToken getAuthentication(String token) {
        Jwt jwt = jwtDecoder.decode(token);
        String username = jwt.getSubject();
        List<String> roles = jwt.getClaimAsStringList("roles");
        List<SimpleGrantedAuthority> authorities = roles.stream().map(SimpleGrantedAuthority::new).toList();
        return new UsernamePasswordAuthenticationToken(username, token, authorities);
    }

    @Override
    public List<String> getRoles(String token) {
        return List.of();
    }

}
