package io.springsecurity.springsecurity6x.security.filter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;

import io.springsecurity.springsecurity6x.security.configurer.state.JwtStateStrategy;
import io.springsecurity.springsecurity6x.security.handler.TokenLogoutHandler;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.utils.CookieUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final TokenLogoutHandler logoutHandler;

    public JwtAuthorizationFilter(TokenService tokenService, TokenLogoutHandler logoutHandler) {
        this.tokenService = tokenService;
        this.logoutHandler = logoutHandler;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest  request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String at = CookieUtil.getToken(request, TokenService.ACCESS_TOKEN);
        String rt = CookieUtil.getToken(request, TokenService.REFRESH_TOKEN);

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            // 1) 액세스 토큰 검사
            if (at != null) {
                try {
                    if (tokenService.validateAccessToken(at)) {
                        Authentication auth = tokenService.getAuthenticationFromToken(at);
                        SecurityContextHolder.getContext().setAuthentication(auth);
                        chain.doFilter(request, response);
                        return;
                    }
                } catch (ExpiredJwtException expiredAt) {
                    // 만료된 액세스 토큰 → 리프레시 단계로
                } catch (JwtException | IllegalArgumentException badAt) {
                    logoutHandler.logout(request, response, authentication);
                    throw new BadCredentialsException("Invalid access token", badAt);
                }
            }

            // 2) 리프레시 토큰이 있을 때만, 명시적 검증 후 재발급
            if (rt != null) {
                try {
                    // 2-1) 리프레시 토큰 유효성 검증
                    if (!tokenService.validateRefreshToken(rt)) {
                        throw new BadCredentialsException("Invalid refresh token");
                    }
                    // 2-2) 검증 통과하면 토큰 재발급
                    Map<String,String> tokens = tokenService.refreshTokens(rt);

                    // 2-3) 쿠키 갱신
                    CookieUtil.addTokenCookie(request, response,
                            TokenService.ACCESS_TOKEN,
                            tokens.get(TokenService.ACCESS_TOKEN),
                            JwtStateStrategy.ACCESS_TOKEN_VALIDITY);
                    CookieUtil.addTokenCookie(request, response,
                            TokenService.REFRESH_TOKEN,
                            tokens.get(TokenService.REFRESH_TOKEN),
                            JwtStateStrategy.REFRESH_TOKEN_VALIDITY);

                    Authentication auth = tokenService.getAuthenticationFromToken(tokens.get(TokenService.ACCESS_TOKEN));
                    SecurityContextHolder.getContext().setAuthentication(auth);

                    chain.doFilter(request, response);
                    return;

                } catch (ExpiredJwtException expiredRt) {
                    logoutHandler.logout(request, response, authentication);
                    throw new BadCredentialsException("Refresh token expired", expiredRt);

                } catch (JwtException | IllegalArgumentException badRt) {
                    logoutHandler.logout(request, response, authentication);
                    throw new BadCredentialsException("Invalid refresh token", badRt);
                }
            }

            chain.doFilter(request, response);
        } finally {
            // 필요 시 후처리
        }
    }

}

