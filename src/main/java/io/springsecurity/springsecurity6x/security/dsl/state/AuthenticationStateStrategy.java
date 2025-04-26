package io.springsecurity.springsecurity6x.security.dsl.state;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;

/**
 * 인증 상태 전략 공통 인터페이스 (JWT / Session)
 */
public interface AuthenticationStateStrategy {
    void init(HttpSecurity http) throws Exception;
    void configure(HttpSecurity http) throws Exception;

    AuthenticationSuccessHandler successHandler();
    AuthenticationFailureHandler failureHandler();
    AuthenticationEntryPoint entryPoint();
    AccessDeniedHandler accessDeniedHandler();
    LogoutHandler logoutHandler();
}


