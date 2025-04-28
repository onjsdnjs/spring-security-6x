package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client.OAuth2HttpClient;
import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client.OAuth2ResourceClient;
import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client.OAuth2TokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class OAuth2AuthenticationFilter extends OncePerRequestFilter {

    private final OAuth2HttpClient httpClient;
    private final OAuth2TokenProvider tokenProvider;
    private final OAuth2ResourceClient resourceClient;

    public OAuth2AuthenticationFilter(OAuth2HttpClient httpClient, OAuth2TokenProvider tokenProvider, OAuth2ResourceClient resourceClient) {
        this.httpClient = httpClient;
        this.tokenProvider = tokenProvider;
        this.resourceClient = resourceClient;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String accessToken = authHeader.substring(7);

            boolean valid = resourceClient.validateAccessToken(accessToken);
            if (valid) {
                Authentication authentication = resourceClient.createAuthentication(accessToken);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}

