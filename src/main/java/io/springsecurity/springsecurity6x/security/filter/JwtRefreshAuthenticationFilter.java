package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.function.Supplier;

public class JwtRefreshAuthenticationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final String refreshUri;
    private final Supplier<LogoutHandler> logoutHandlerSupplier;

    public JwtRefreshAuthenticationFilter(TokenService tokenService, Supplier<LogoutHandler> logoutHandlerSupplier) {
        this.tokenService     = tokenService;
        this.refreshUri       = tokenService.properties().getInternal().getRefreshUri();
        this.logoutHandlerSupplier = logoutHandlerSupplier;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {

        if (!refreshUri.equals(request.getRequestURI())) {
            chain.doFilter(request, response);
            return;
        }
        String token = tokenService.resolveRefreshToken(request);
        if (StringUtils.hasText(token)) {
            try {
                TokenService.RefreshResult result = tokenService.refresh(token);
                tokenService.writeAccessAndRefreshToken(response, result.accessToken(), result.refreshToken());
            } catch (Exception e) {
                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                LogoutHandler logoutHandler = logoutHandlerSupplier.get();
                logoutHandler.logout(request, response, auth);
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 로그인 상태가 아님: 정상 흐름
            }
        } else {
            response.setStatus(HttpServletResponse.SC_NO_CONTENT); // 로그인 상태가 아님: 정상 흐름
        }
        chain.doFilter(request, response);
    }
}

