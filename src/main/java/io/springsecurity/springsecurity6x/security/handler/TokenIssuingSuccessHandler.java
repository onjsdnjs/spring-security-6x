package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;

import java.io.IOException;

/**
 * 원본 AuthenticationSuccessHandler 앞뒤에 토큰 발급 로직을 삽입하는 데코레이터
 */
@Slf4j
public class TokenIssuingSuccessHandler implements AuthenticationSuccessHandler {
    private final TokenService tokenService;
    private final AuthenticationSuccessHandler delegate;

    public TokenIssuingSuccessHandler(TokenService tokenService,
                                      AuthenticationSuccessHandler delegate) {
        this.tokenService = tokenService;
        this.delegate     = delegate;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        String deviceId = request.getHeader("X-Device-Id");
        if (!StringUtils.hasText(deviceId)) {
            throw new BadCredentialsException("Device ID missing");
        }
        try {
            String access  = tokenService.createAccessToken(authentication, deviceId);
            String refresh = tokenService.createRefreshToken(authentication, deviceId);
            tokenService.writeAccessAndRefreshToken(response, access, refresh);
        } catch (Exception e) {
            log.error("Token creation or response writing failed", e);
            throw new AuthenticationServiceException("토큰 발급 실패", e);
        }

        // 2) 원본 성공 핸들러 호출 (redirect 등)
        delegate.onAuthenticationSuccess(request, response, authentication);
    }
}

