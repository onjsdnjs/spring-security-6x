package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportResult;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

public interface PlatformAuthenticationSuccessHandler extends AuthenticationSuccessHandler {
    void onAuthenticationSuccess(HttpServletRequest request,
                                 HttpServletResponse response,
                                 Authentication authentication,
                                 TokenTransportResult result) throws IOException, ServletException;

    // 기존 onAuthenticationSuccess 메서드는 default로 구현하거나, 호출되지 않도록 처리
    @Override
    default void onAuthenticationSuccess(HttpServletRequest request,
                                         HttpServletResponse response,
                                         Authentication authentication) throws IOException, ServletException {

    }
}
