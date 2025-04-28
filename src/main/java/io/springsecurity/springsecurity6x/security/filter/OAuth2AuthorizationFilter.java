package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client.OAuth2HttpClient;
import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client.OAuth2ResourceClient;
import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client.OAuth2TokenProvider;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class OAuth2AuthorizationFilter extends OncePerRequestFilter {

    private final OAuth2HttpClient httpClient;
    private final OAuth2TokenProvider tokenProvider;
    private final OAuth2ResourceClient resourceClient;
    private final TokenTransportStrategy transport;
    private final LogoutHandler logoutHandler;

    public OAuth2AuthorizationFilter(OAuth2HttpClient httpClient,
                                      OAuth2TokenProvider tokenProvider,
                                      OAuth2ResourceClient resourceClient,
                                      TokenTransportStrategy transport,
                                      LogoutHandler logoutHandler) {
        this.httpClient = httpClient;
        this.tokenProvider = tokenProvider;
        this.resourceClient = resourceClient;
        this.transport = transport;
        this.logoutHandler = logoutHandler;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String accessToken = transport.resolveAccessToken(request);

        if (accessToken != null) {
            try {
                boolean valid = resourceClient.validateAccessToken(accessToken);
                if (!valid) {
                    throw new IllegalStateException("Invalid OAuth2 access token");
                }
                // ✅ 토큰은 유효하지만, 인증 객체(Authentication)는 별도로 세팅하지 않음 (API 보호용)
            } catch (Exception e) {
                SecurityContextHolder.clearContext();
                logoutHandler.logout(request, response, null);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid access token");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}

