package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final LogoutHandler logoutHandler;

    public JwtAuthorizationFilter(TokenService tokenService, LogoutHandler logoutHandler) {
        this.tokenService = tokenService;
        this.logoutHandler = logoutHandler;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || authenticationTrustResolver.isAnonymous(authentication)) {
            String accessToken = tokenService.resolveAccessToken(request);
            if (accessToken != null) {
                try {
                    if (tokenService.validateAccessToken(accessToken)) {
                        Authentication auth = tokenService.getAuthentication(accessToken);
                        SecurityContextHolder.getContext().setAuthentication(auth);
                    }
                } catch (Exception e) {
                    logoutHandler.logout(request, response, null);
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid access token");
                    return;
                }
            }
        }

        chain.doFilter(request, response);
    }
}


