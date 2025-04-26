package io.springsecurity.springsecurity6x.security.dsl.state;

package io.springsecurity.dsl;

import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import jakarta.servlet.http.HttpServletResponse;

/**
 * Session 기반 인증 상태 전략
 */
public class SessionStateStrategy implements AuthenticationStateStrategy {
    private final String loginPage;

    public SessionStateStrategy(String loginPage) {
        this.loginPage = loginPage;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        // 세션 기본 사용, 별도 설정 없음
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(entryPoint())
                        .accessDeniedHandler(accessDeniedHandler())
                )
                .logout(logout -> logout.logoutSuccessUrl(loginPage + "?logout"));
    }

    @Override
    public AuthenticationSuccessHandler successHandler() {
        return (request, response, authentication) -> response.sendRedirect("/");
    }

    @Override
    public AuthenticationFailureHandler failureHandler() {
        return (request, response, exception) -> response.sendRedirect(loginPage + "?error");
    }

    @Override
    public AuthenticationEntryPoint entryPoint() {
        return new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);
    }

    @Override
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, exception) -> response.sendError(HttpServletResponse.SC_FORBIDDEN, "접근 거부");
    }

    @Override
    public LogoutHandler logoutHandler() {
        return (request, response, authentication) -> {
            // 기본 세션 클리어 처리
        };
    }
}
