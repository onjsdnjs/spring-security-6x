package io.springsecurity.springsecurity6x.jwt.tokenservice;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class JwtTokenService implements TokenService {

    private final String secret = "very-secret-key";
    private final Map<String, String> refreshStore = new ConcurrentHashMap<>();
    private final AuthenticationManager authManager;
    private final long accessTokenValidity = 3600000;
    private final long refreshTokenValidity = 604800000;

    public JwtTokenService(AuthenticationManager authManager) {
        this.authManager = authManager;
    }

    @Override
    public String createAccessToken(String username, List<String> roles) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", roles);
        Date now = new Date();

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + accessTokenValidity))
                .signWith(SignatureAlgorithm.HS256, secret.getBytes())
                .compact();
    }

    @Override
    public String createRefreshToken(String username) {
        String refreshToken = UUID.randomUUID().toString();
        refreshStore.put(refreshToken, username);
        return refreshToken;
    }

    @Override
    public boolean validateAccessToken(String token) {
        try {
            Jwts.parser().setSigningKey(secret.getBytes()).parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public Authentication getAuthenticationFromAccessToken(String token) {
        Claims claims = Jwts.parser().setSigningKey(secret.getBytes()).parseClaimsJws(token).getBody();
        String username = claims.getSubject();
        List<String> roles = claims.get("roles", List.class);
        List<SimpleGrantedAuthority> authorities = roles.stream().map(SimpleGrantedAuthority::new).toList();
        return new UsernamePasswordAuthenticationToken(username, "", authorities);
    }

    @Override
    public String refreshAccessToken(String refreshToken) {
        String username = refreshStore.get(refreshToken);
        if (username == null) throw new RuntimeException("Invalid refresh token");
        return createAccessToken(username, List.of("ROLE_USER"));
    }

    @Override
    public void invalidateToken(String refreshToken) {
        refreshStore.remove(refreshToken);
    }

    @Override
    public AuthenticationManager getAuthenticationManager() {
        return authManager;
    }
}

