package io.springsecurity.springsecurity6x.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

public class JwtRefreshAuthenticationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final TokenTransportStrategy transportHandler;
    private final String refreshUri;

    public JwtRefreshAuthenticationFilter(TokenService tokenService,
                                          TokenTransportStrategy transportHandler,
                                          AuthContextProperties properties) {
        this.tokenService     = tokenService;
        this.transportHandler = transportHandler;
        this.refreshUri       = properties.getInternal().getRefreshUri();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {

        if (!refreshUri.equals(req.getRequestURI())) {
            chain.doFilter(req, res);
            return;
        }

        String token = transportHandler.resolveRefreshToken(req);
        try {
            TokenService.RefreshResult result = tokenService.refresh(token);

            transportHandler.writeAccessToken(res, result.accessToken());
            transportHandler.writeRefreshToken(res, result.refreshToken());

            res.setStatus(HttpServletResponse.SC_OK);
            res.setContentType("application/json;charset=UTF-8");
            new ObjectMapper().writeValue(res.getWriter(), Map.of("message", "Refresh successful"));

        } catch (Exception e) {
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Refresh token invalid");
        }
    }
}

