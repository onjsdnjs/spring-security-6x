package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.util.StringUtils;

import java.io.IOException;

/**
 * 마지막 로그인 처리 URL POST 요청에만 동작하여,
 * 인증 성공 시 한 번만 JWT Access/Refresh Token을 생성·전송합니다.
 */
@Slf4j
public class JwtTokenIssuerFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final RequestMatcher loginMatcher;

    public JwtTokenIssuerFilter(TokenService tokenService, RequestMatcher loginMatcher) {
        this.tokenService  = tokenService;
        this.loginMatcher  = loginMatcher;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // 로그인 처리 POST URL이 아니면 스킵
        return !loginMatcher.matches(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || response.isCommitted()) {
            return;
        }

        String deviceId = request.getHeader("X-Device-Id");
        if (!StringUtils.hasText(deviceId)) {
            throw new BadCredentialsException("Device ID is missing");
        }

        String accessToken = tokenService.createAccessToken(auth, deviceId);
        String refreshToken = tokenService.createRefreshToken(auth, deviceId);
        try {
            tokenService.writeAccessAndRefreshToken(response, accessToken, refreshToken);
        } catch (Exception e) {
            log.error("Token creation or response writing failed", e);
            throw new AuthenticationServiceException("토큰 발급 실패", e);
        }

        chain.doFilter(request, response);
    }
}

