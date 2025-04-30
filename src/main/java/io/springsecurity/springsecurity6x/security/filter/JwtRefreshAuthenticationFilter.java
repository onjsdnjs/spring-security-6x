package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtRefreshAuthenticationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final String refreshUri;

    public JwtRefreshAuthenticationFilter(TokenService tokenService,
                                          AuthContextProperties properties) {
        this.tokenService     = tokenService;
        this.refreshUri       = properties.getInternal().getRefreshUri();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {

        if (!refreshUri.equals(req.getRequestURI())) {
            chain.doFilter(req, res);
            return;
        }
        String token = tokenService.resolveRefreshToken(req);
        try {
            TokenService.RefreshResult result = tokenService.refresh(token);
            tokenService.writeAccessAndRefreshToken(res, result.accessToken(), result.refreshToken());

        } catch (Exception e) {
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Refresh token invalid");
        }
    }
}

