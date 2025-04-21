package io.springsecurity.springsecurity6x.jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.domain.LoginRequest;
import io.springsecurity.springsecurity6x.jwt.tokenservice.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private TokenService tokenService;
    private String tokenPrefix;
    private long accessTokenValidity;
    private long refreshTokenValidity;
    private String loginUri;
    private String rolesClaim;
    private boolean enableRefreshToken;
    private Map<String, String> scopeToPattern = new HashMap<>();

    public JwtAuthenticationFilter() {
        super(new AntPathRequestMatcher("/api/auth/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException {

        ObjectMapper mapper = new ObjectMapper();
        LoginRequest login = mapper.readValue(request.getInputStream(), LoginRequest.class);
        String username = login.username();
        String password = login.password();

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        String username = authResult.getName();
        List<String> roles = authResult.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList();

        Map<String, Object> additionalClaims = new HashMap<>();
        additionalClaims.put(rolesClaim, roles);

        String accessToken = tokenService.createAccessToken(builder -> builder
                .username(username)
                .roles(roles)
                .claims(additionalClaims)
                .validity(accessTokenValidity));

        String refreshToken = enableRefreshToken ?
                tokenService.createRefreshToken(builder -> builder
                        .username(username)
                        .validity(refreshTokenValidity)) : null;

        Map<String, Object> tokens = new HashMap<>();
        tokens.put("accessToken", tokenPrefix + accessToken);
        if (refreshToken != null) tokens.put("refreshToken", tokenPrefix + refreshToken);

        response.addHeader("accessToken", accessToken);
        response.addHeader("refreshToken", refreshToken);

        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(), Map.of("error", "Authentication failed"));
    }

    public void setTokenService(TokenService tokenService) { this.tokenService = tokenService; }
    public void setTokenPrefix(String tokenPrefix) { this.tokenPrefix = tokenPrefix; }
    public void setAccessTokenValidity(long accessTokenValidity) { this.accessTokenValidity = accessTokenValidity; }
    public void setRefreshTokenValidity(long refreshTokenValidity) { this.refreshTokenValidity = refreshTokenValidity; }
    public void setLoginUri(String loginUri) { this.loginUri = loginUri; }
    public void setRolesClaim(String rolesClaim) { this.rolesClaim = rolesClaim; }
    public void setEnableRefreshToken(boolean enableRefreshToken) { this.enableRefreshToken = enableRefreshToken; }
}

