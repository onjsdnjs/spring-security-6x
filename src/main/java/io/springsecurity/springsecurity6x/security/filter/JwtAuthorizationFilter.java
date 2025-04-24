package io.springsecurity.springsecurity6x.security.filter;

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
                Authentication auth = tokenService.getAuthenticationFromAccessToken(accessToken);
                SecurityContextHolder.getContext().setAuthentication(auth);

            } else if (refreshToken != null && tokenService.validateAccessToken(refreshToken)) {
                // 2) 액세스 토큰이 없거나 만료됐으면, 리프레시 → 새 액세스 토큰 발급
                String newAccessToken = tokenService.refreshAccessToken(refreshToken);

                // 2-1) 새 액세스 토큰을 쿠키에 담아서 응답
                CookieUtil.addTokenCookie(request, response, "accessToken", newAccessToken);

                // 2-2) 컨텍스트에 인증 정보 세팅
                Authentication auth = tokenService.getAuthenticationFromAccessToken(newAccessToken);
                SecurityContextHolder.getContext().setAuthentication(auth);

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

