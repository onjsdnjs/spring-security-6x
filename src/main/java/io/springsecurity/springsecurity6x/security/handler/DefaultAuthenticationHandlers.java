package io.springsecurity.springsecurity6x.security.handler;

import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

/**
 * 인증 성공/실패에 대한 기본 핸들러 구현체.
 * (토큰을 사용하지 않는 전통적인 세션 흐름용)
 */
public class DefaultAuthenticationHandlers implements AuthenticationHandlers {

    private final SimpleUrlAuthenticationSuccessHandler successHandler;
    private final SimpleUrlAuthenticationFailureHandler failureHandler;

    public DefaultAuthenticationHandlers() {
        // 로그인 성공 시 "/" 로 리다이렉트
        this.successHandler = new SimpleUrlAuthenticationSuccessHandler("/");
        // 로그인 실패 시 "/login?error" 로 리다이렉트
        this.failureHandler = new SimpleUrlAuthenticationFailureHandler("/login?error");
    }

    @Override
    public AuthenticationSuccessHandler successHandler() {
        return successHandler;
    }

    @Override
    public AuthenticationFailureHandler failureHandler() {
        return failureHandler;
    }
}

