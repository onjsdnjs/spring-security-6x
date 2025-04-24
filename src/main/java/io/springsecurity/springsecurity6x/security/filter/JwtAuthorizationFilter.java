package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.configurer.state.JwtStateStrategy;
import io.springsecurity.springsecurity6x.security.tokenservice.TokenService;
import io.springsecurity.springsecurity6x.security.utils.CookieUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;

    public JwtAuthorizationFilter(TokenService tokenService) {
        this.tokenService                = tokenService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest  request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String accessToken  = resolveCookie(request, "accessToken");
        String refreshToken = resolveCookie(request, "refreshToken");

        try {
            if (accessToken != null && tokenService.validateAccessToken(accessToken)) {
                // 1) 액세스 토큰이 유효하면 바로 인증 세팅
                Authentication auth = tokenService.getAuthenticationFromToken(accessToken);
                SecurityContextHolder.getContext().setAuthentication(auth);

            } else if (refreshToken != null && tokenService.validateAccessToken(refreshToken)) {
                // 2) 액세스 토큰 만료 시 → 리프레시 토큰 검사
                if (!tokenService.shouldRotateRefreshToken(refreshToken)) {
                    // 2-1) 회전 불필요: RT 그대로, AT만 재발급
                    String newAccessToken = tokenService.createAccessTokenFromRefresh(refreshToken);
                    CookieUtil.addTokenCookie(request, response,TokenService.ACCESS_TOKEN, newAccessToken, JwtStateStrategy.ACCESS_TOKEN_VALIDITY);

                    Authentication auth = tokenService.getAuthenticationFromToken(newAccessToken);
                    SecurityContextHolder.getContext().setAuthentication(auth);

                } else {
                    // 2-2) 회전 필요: RT + AT 모두 재발급
                    Map<String,String> tokens = tokenService.refreshTokens(refreshToken);

                    String newAccessToken  = tokens.get(TokenService.ACCESS_TOKEN);
                    String newRefreshToken = tokens.get(TokenService.REFRESH_TOKEN);

                    CookieUtil.addTokenCookie(request, response, TokenService.ACCESS_TOKEN,  newAccessToken,  JwtStateStrategy.ACCESS_TOKEN_VALIDITY);
                    CookieUtil.addTokenCookie(request, response, TokenService.REFRESH_TOKEN, newRefreshToken, JwtStateStrategy.REFRESH_TOKEN_VALIDITY);

                    Authentication auth = tokenService.getAuthenticationFromToken(newAccessToken);
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            }

        } catch (RuntimeException ex) {
            // 리프레시 중 에러(만료, 위조 토큰 등) 발생 시에도 같은 처리
            clearCookies(response);
            response.sendRedirect(request.getContextPath() + "/loginForm");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private String resolveCookie(HttpServletRequest req, String name) {
        if (req.getCookies() == null) return null;
        return Arrays.stream(req.getCookies())
                .filter(c -> name.equals(c.getName()))
                .findFirst()
                .map(Cookie::getValue)
                .orElse(null);
    }

    private void clearCookies(HttpServletResponse res) {
        List<String> names = List.of("accessToken", "refreshToken");
        for (String name : names) {
            Cookie c = new Cookie(name, "");
            c.setPath("/");
            c.setHttpOnly(true);
            c.setMaxAge(0);
            res.addCookie(c);
        }
    }
}

