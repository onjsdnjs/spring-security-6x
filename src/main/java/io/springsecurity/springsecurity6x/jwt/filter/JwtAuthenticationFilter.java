package io.springsecurity.springsecurity6x.jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.jwt.JwtProperties;
import io.springsecurity.springsecurity6x.jwt.annotation.RefreshTokenStore;
import io.springsecurity.springsecurity6x.jwt.domain.LoginRequest;
import io.springsecurity.springsecurity6x.jwt.tokenservice.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private TokenService tokenService;
    private RefreshTokenStore refreshTokenStore;
    private String tokenPrefix;
    private long accessTokenValidity;
    private long refreshTokenValidity;
    private String loginUri;
    private String logoutUri;
    private String refreshUri;
    private String rolesClaim;
    private String scopesClaim;
    private boolean enableRefreshToken;
    private Map<String, String> scopeToPattern = new HashMap<>();

    public JwtAuthenticationFilter() {
        super(new AntPathRequestMatcher("/api/auth/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, String> body = mapper.readValue(request.getInputStream(), Map.class);
        String username = body.get("username");
        String password = body.get("password");

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
        String username = authResult.getName();
        List<String> roles = authResult.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList();

        String accessToken = tokenService.createAccessToken(username, roles);
        String refreshToken = enableRefreshToken ? tokenService.createRefreshToken(username) : null;

        Map<String, Object> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        if (refreshToken != null) tokens.put("refreshToken", refreshToken);

        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(), Map.of("error", "Authentication failed"));
    }

    // --- Setters ---
    public void setTokenService(TokenService tokenService) { this.tokenService = tokenService; }
    public void setRefreshTokenStore(RefreshTokenStore refreshTokenStore) { this.refreshTokenStore = refreshTokenStore; }
    public void setTokenPrefix(String tokenPrefix) { this.tokenPrefix = tokenPrefix; }
    public void setAccessTokenValidity(long accessTokenValidity) { this.accessTokenValidity = accessTokenValidity; }
    public void setRefreshTokenValidity(long refreshTokenValidity) { this.refreshTokenValidity = refreshTokenValidity; }
    public void setLoginUri(String loginUri) { this.loginUri = loginUri; }
    public void setLogoutUri(String logoutUri) { this.logoutUri = logoutUri; }
    public void setRefreshUri(String refreshUri) { this.refreshUri = refreshUri; }
    public void setRolesClaim(String rolesClaim) { this.rolesClaim = rolesClaim; }
    public void setScopesClaim(String scopesClaim) { this.scopesClaim = scopesClaim; }
    public void setEnableRefreshToken(boolean enableRefreshToken) { this.enableRefreshToken = enableRefreshToken; }
    public void setScopeToPattern(Map<String, String> scopeToPattern) { this.scopeToPattern = scopeToPattern; }
}

