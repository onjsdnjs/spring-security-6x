package io.springsecurity.springsecurity6x.jwt.tokenservice;

import io.springsecurity.springsecurity6x.jwt.annotation.RefreshTokenStore;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.*;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public class SpringJwtTokenService implements TokenService {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final AuthenticationManager authManager;
    private final RefreshTokenStore refreshTokenStore;

    private final long accessTokenValidity = 3600; // seconds
    private final long refreshTokenValidity = 604800; // seconds

    public SpringJwtTokenService(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder,
                                 AuthenticationManager authManager,
                                 RefreshTokenStore refreshTokenStore) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.authManager = authManager;
        this.refreshTokenStore = refreshTokenStore;
    }

    @Override
    public String createAccessToken(String username, List<String> roles) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(username)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(accessTokenValidity))
                .claim("roles", roles)
                .build();

        JwsHeader jwsHeader = JwsHeader.with(() -> "RS256").build();
        return jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims)).getTokenValue();
    }

    @Override
    public String createRefreshToken(String username) {
        String refreshToken = UUID.randomUUID().toString();
        refreshTokenStore.store(refreshToken, username);
        return refreshToken;
    }

    @Override
    public boolean validateAccessToken(String token) {
        try {
            jwtDecoder.decode(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    @Override
    public Authentication getAuthenticationFromAccessToken(String token) {
        Jwt jwt = jwtDecoder.decode(token);
        String username = jwt.getSubject();
        List<String> roles = jwt.getClaimAsStringList("roles");
        List<SimpleGrantedAuthority> authorities = roles.stream().map(SimpleGrantedAuthority::new).toList();
        return new UsernamePasswordAuthenticationToken(username, "", authorities);
    }

    @Override
    public String refreshAccessToken(String refreshToken) {
        String username = refreshTokenStore.getUsername(refreshToken);
        if (username == null) throw new RuntimeException("Invalid refresh token");
        return createAccessToken(username, List.of("ROLE_USER"));
    }

    @Override
    public void invalidateToken(String refreshToken) {
        refreshTokenStore.remove(refreshToken);
    }

    @Override
    public AuthenticationManager getAuthenticationManager() {
        return authManager;
    }
}

