package io.springsecurity.springsecurity6x.security.configurer.state;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.tokenservice.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JwtStateStrategy implements AuthenticationStateStrategy {

    private TokenService tokenService;
    private String tokenPrefix = "Bearer ";
    private long accessTokenValidity = 3600000;     // default: 1 hour
    private long refreshTokenValidity = 604800000;  // default: 7 days
    private boolean enableRefreshToken = true;

    public JwtStateStrategy tokenService(TokenService tokenService) {
        this.tokenService = tokenService;
        return this;
    }

    public JwtStateStrategy tokenPrefix(String prefix) {
        this.tokenPrefix = prefix;
        return this;
    }

    public JwtStateStrategy accessTokenValidity(long millis) {
        this.accessTokenValidity = millis;
        return this;
    }

    public JwtStateStrategy refreshTokenValidity(long millis) {
        this.refreshTokenValidity = millis;
        return this;
    }

    public JwtStateStrategy enableRefreshToken(boolean enable) {
        this.enableRefreshToken = enable;
        return this;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        String username = authentication.getName();
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList();

        String accessToken = tokenService.createAccessToken(builder -> builder
                .username(username)
                .roles(roles)
                .validity(accessTokenValidity));

        String refreshToken = enableRefreshToken
                ? tokenService.createRefreshToken(builder -> builder
                .username(username)
                .validity(refreshTokenValidity))
                : null;

        Map<String, Object> result = new HashMap<>();
        result.put("accessToken", tokenPrefix + accessToken);
        if (refreshToken != null) result.put("refreshToken", tokenPrefix + refreshToken);

        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(), result);
    }
}

