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

        String accessToken = CookieUtil.getToken(request, TokenService.ACCESS_TOKEN);
        String refreshToken = CookieUtil.getToken(request, TokenService.REFRESH_TOKEN);

        // 1) 액세스 토큰 검사
        if (accessToken != null) {
            try {
                if (tokenService.validateAccessToken(accessToken)) {
                    Authentication auth = tokenService.getAuthenticationFromToken(accessToken);
                    SecurityContextHolder.getContext().setAuthentication(auth);
                    chain.doFilter(request, response);
                    return;
                }
            } catch (ExpiredJwtException expiredAt) {
                System.out.println("ExpiredJwtException = " + expiredAt.getMessage());

            } catch (JwtException | IllegalArgumentException badAt) {
                // 모든 토큰 강제 만료, 인증정보 삭제, 토큰 저장 삭제
                logoutHandler.logout(request, response, SecurityContextHolder.getContext().getAuthentication());
                throw new BadCredentialsException("Invalid access token", badAt);
            }
        }else {
            chain.doFilter(request, response);
            return;
        }

        if (refreshToken == null) {
            chain.doFilter(request, response);
            return;
        }
        try {
            // 2-1) 리프레시 토큰 유효성 검증
            if (!tokenService.validateRefreshToken(refreshToken)) {
                throw new BadCredentialsException("Invalid refresh token");
            }
            // 2-2) 검증 통과하면 토큰 재발급
            Map<String,String> tokens = tokenService.refreshTokens(refreshToken);

            // 2-3) 쿠키 갱신
            CookieUtil.addTokenCookie(request, response, TokenService.ACCESS_TOKEN, tokens.get(TokenService.ACCESS_TOKEN));
            CookieUtil.addTokenCookie(request, response, TokenService.REFRESH_TOKEN, tokens.get(TokenService.REFRESH_TOKEN));

            Authentication auth = tokenService.getAuthenticationFromToken(tokens.get(TokenService.ACCESS_TOKEN));
            SecurityContextHolder.getContext().setAuthentication(auth);

            chain.doFilter(request, response);

        } catch (ExpiredJwtException expiredRt) {
            logoutHandler.logout(request, response, SecurityContextHolder.getContext().getAuthentication());
            throw new BadCredentialsException("Refresh token expired", expiredRt);

        } catch (JwtException | IllegalArgumentException badRt) {
            logoutHandler.logout(request, response, SecurityContextHolder.getContext().getAuthentication());
            throw new BadCredentialsException("Invalid refresh token", badRt);
        }
    }

}

