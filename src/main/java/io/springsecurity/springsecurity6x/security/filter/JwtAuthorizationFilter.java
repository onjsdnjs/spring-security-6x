package io.springsecurity.springsecurity6x.security.filter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.springsecurity.springsecurity6x.security.handler.TokenLogoutHandler;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportHandler;
import io.springsecurity.springsecurity6x.security.utils.CookieUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final TokenTransportHandler  transportHandler;
    private final LogoutHandler logoutHandler;

    public JwtAuthorizationFilter(TokenService tokenService, TokenTransportHandler transportHandler, LogoutHandler logoutHandler) {
        this.tokenService = tokenService;
        this.logoutHandler = logoutHandler;
        this.transportHandler = transportHandler;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest  request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String accessToken = transportHandler.resolveAccessToken(request);
        String refreshToken = transportHandler.resolveRefreshToken(request);

        if (accessToken != null) {
            try {
                if (tokenService.validateAccessToken(accessToken)) {
                    Authentication auth = tokenService.getAuthenticationFromToken(accessToken);
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            } catch (ExpiredJwtException e) {
                // accessToken 만료: 무시하고 refreshToken 검사로 넘어감
            } catch (Exception e) {
                failAndLogout(request, response, SecurityContextHolder.getContext().getAuthentication(), "Invalid access token", e);
                return;
            }
        }

        if (SecurityContextHolder.getContext().getAuthentication() == null && refreshToken != null) {
            try {
                Map<String, String> tokens = tokenService.refreshTokens(refreshToken);
                transportHandler.sendAccessToken(response, tokens.get(TokenService.ACCESS_TOKEN));
                transportHandler.sendRefreshToken(response, tokens.get(TokenService.REFRESH_TOKEN));

                Authentication auth = tokenService.getAuthenticationFromToken(tokens.get(TokenService.ACCESS_TOKEN));
                SecurityContextHolder.getContext().setAuthentication(auth);

            } catch (Exception e) {
                failAndLogout(request, response, SecurityContextHolder.getContext().getAuthentication(), "Invalid refresh token", e);
                return;
            }
        }

        chain.doFilter(request, response);
    }

    private void failAndLogout(HttpServletRequest req, HttpServletResponse res, Authentication authentication, String msg, Exception e) {
        logoutHandler.logout(req,res, authentication);
        throw new BadCredentialsException(msg, e);
    }
}

