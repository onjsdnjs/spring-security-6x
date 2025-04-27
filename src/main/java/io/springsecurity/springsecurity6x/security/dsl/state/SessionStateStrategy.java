package io.springsecurity.springsecurity6x.security.dsl.state;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import java.io.IOException;

/**
 * Session 기반 인증 상태 전략
 */
public class SessionStateStrategy implements AuthenticationStateStrategy {

    private final AuthContextProperties properties;

    public SessionStateStrategy(AuthContextProperties properties) {
        this.properties = properties;
    }

    @Override
    public void init(HttpSecurity http) { /* 기본 Spring Security 세션 흐름 그대로 */ }

    @Override
    public void configure(HttpSecurity http) { /* 필요 시 추가 세션 설정 */ }

    @Override
    public AuthenticationSuccessHandler successHandler() {
        return (req, res, auth) -> res.sendRedirect("/");
    }

    @Override
    public AuthenticationFailureHandler failureHandler() {
        return (req, res, ex) -> res.sendRedirect("/login?error");
    }

    @Override
    public AuthenticationEntryPoint entryPoint() {
        return new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);
    }

    @Override
    public AccessDeniedHandler accessDeniedHandler() {
        return (req, res, ex) -> res.sendRedirect("/access-denied");
    }

    @Override
    public LogoutHandler logoutHandler() {
        return (req, res, auth) -> {
            try {
                res.sendRedirect("/login?logout");
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        };
    }
}
