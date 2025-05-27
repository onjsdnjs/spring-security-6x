package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;

@Slf4j
public class RestAuthenticationFilter extends BaseAuthenticationFilter {

    public RestAuthenticationFilter(RequestMatcher requestMatcher, AuthenticationManager authenticationManager,
                                    AuthContextProperties properties) {
        super(requestMatcher, authenticationManager, properties);
        log.info("SimpleAuthenticationFilter initialized for single-factor authentication");
    }
    /**
     * 인증 성공 처리 - 분산환경 완전 대응
     */
    public void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                          Authentication authentication) throws IOException, ServletException {
        // Security Context 설정
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);
        successHandler.onAuthenticationSuccess(request, response, authentication);
    }

    /**
     * 인증 실패 처리
     */
    public void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException failed) throws IOException, ServletException {
        securityContextHolderStrategy.clearContext();
        failureHandler.onAuthenticationFailure(request, response, failed);
    }
}
