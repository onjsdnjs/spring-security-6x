package io.springsecurity.springsecurity6x.security.handler.authentication;

import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;

public interface AuthenticationHandlers {

    default AuthenticationSuccessHandler successHandler() {
        return (request, response, authentication) -> {
            response.sendRedirect("/");
        };
    }

    default AuthenticationFailureHandler failureHandler() {
        return (request, response, exception) -> {
            response.sendRedirect("/login?error");
        };
    }

    default LogoutHandler logoutHandler() {
        return (request, response, authentication) -> {

        };
    }
}


