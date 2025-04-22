package io.springsecurity.springsecurity6x.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.tokenservice.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

public class JwtRefreshTokenFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final String refreshUri;

    public JwtRefreshTokenFilter(TokenService tokenService, String refreshUri) {
        this.tokenService = tokenService;
        this.refreshUri = refreshUri;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().equals(refreshUri);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, jakarta.servlet.FilterChain filterChain) throws IOException {

        Map<String, String> body = new ObjectMapper().readValue(request.getInputStream(), Map.class);
        String refreshToken = body.get("refreshToken");
        String accessToken = tokenService.refreshAccessToken(refreshToken);

        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(), Map.of("accessToken", "Bearer " + accessToken));
    }
}