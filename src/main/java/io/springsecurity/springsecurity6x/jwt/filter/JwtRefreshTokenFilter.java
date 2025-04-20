package io.springsecurity.springsecurity6x.jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.jwt.annotation.RefreshTokenStore;
import io.springsecurity.springsecurity6x.jwt.tokenservice.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public class JwtRefreshTokenFilter extends AbstractAuthenticationProcessingFilter {

    private TokenService tokenService;
    private RefreshTokenStore refreshTokenStore;

    public JwtRefreshTokenFilter(String refreshUri) {
        super(new AntPathRequestMatcher(refreshUri, "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {

        Map<String, String> body = new ObjectMapper().readValue(request.getInputStream(), Map.class);
        String refreshToken = body.get("refreshToken");

        String username = refreshTokenStore.getUsername(refreshToken);
        if (username == null) {
            throw new BadCredentialsException("Invalid refresh token");
        }

        String accessToken = tokenService.createAccessToken(username, List.of("ROLE_USER"));

        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(), Map.of("accessToken", accessToken));

        // 인증 객체 반환은 안 하지만 흐름 제어를 위해 null 반환
        return null;
    }

    public void setTokenService(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    public void setRefreshTokenStore(RefreshTokenStore refreshTokenStore) {
        this.refreshTokenStore = refreshTokenStore;
    }
}