package io.springsecurity.springsecurity6x.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.TokenCreator;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportHandler;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.Map;

public class JwtRefreshAuthenticationFilter extends OncePerRequestFilter {

    private final TokenValidator tokenValidator;
    private final TokenCreator tokenCreator;
    private final TokenTransportHandler tokenTransportHandler;
    private final RefreshTokenStore refreshTokenStore;
    private final AuthContextProperties properties;
    private final String refreshUri;

    public JwtRefreshAuthenticationFilter(
            TokenValidator tokenValidator,
            TokenCreator tokenCreator,
            TokenTransportHandler tokenTransportHandler,
            RefreshTokenStore refreshTokenStore,
            AuthContextProperties properties
    ) {
        this.tokenValidator = tokenValidator;
        this.tokenCreator = tokenCreator;
        this.tokenTransportHandler = tokenTransportHandler;
        this.refreshTokenStore = refreshTokenStore;
        this.properties = properties;
        this.refreshUri = properties.getInternal().getRefreshUri();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (!refreshUri.equals(request.getRequestURI())) {
            chain.doFilter(request, response);
            return;
        }

        String refreshToken = tokenTransportHandler.extractRefreshToken(request);
        if (refreshToken == null || !tokenValidator.validateRefreshToken(refreshToken)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid refresh token");
            return;
        }

        try {
            String username = refreshTokenStore.getUsername(refreshToken);
            if (username == null) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Refresh token expired or revoked");
                return;
            }

            String newAccessToken = tokenCreator.builder()
                    .tokenType("access")
                    .username(username)
                    .validity(properties.getInternal().getAccessTokenValidity())
                    .build();

            String newRefreshToken;
            if (properties.getInternal().isEnableRefreshToken() && tokenValidator.shouldRotateRefreshToken(refreshToken)) {
                refreshTokenStore.remove(refreshToken);

                newRefreshToken = tokenCreator.builder()
                        .tokenType("refresh")
                        .username(username)
                        .validity(properties.getInternal().getRefreshTokenValidity())
                        .build();

                refreshTokenStore.store(newRefreshToken, username);
            } else {
                newRefreshToken = refreshToken;
            }

            tokenTransportHandler.sendAccessToken(response, newAccessToken);
            if (newRefreshToken != null) {
                tokenTransportHandler.sendRefreshToken(response, newRefreshToken);
            }

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json;charset=UTF-8");
            new ObjectMapper().writeValue(response.getWriter(), Map.of(
                    "message", "Refresh successful"
            ));

        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Refresh token invalid");
        }
    }
}

