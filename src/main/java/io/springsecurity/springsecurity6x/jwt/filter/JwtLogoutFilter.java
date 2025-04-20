package io.springsecurity.springsecurity6x.jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.jwt.tokenservice.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

public class JwtLogoutFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final String logoutUri;

    public JwtLogoutFilter(TokenService tokenService, String logoutUri) {
        this.tokenService = tokenService;
        this.logoutUri = logoutUri;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().equals(logoutUri);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, jakarta.servlet.FilterChain filterChain) throws IOException {

        Map<String, String> body = new ObjectMapper().readValue(request.getInputStream(), Map.class);
        String refreshToken = body.get("refreshToken");
        tokenService.invalidateToken(refreshToken);

        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(), Map.of("message", "Logged out successfully"));
    }
}
