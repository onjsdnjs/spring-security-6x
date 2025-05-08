package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.function.Supplier;

/**
 * TokenService를 직접 들고 있지 않고, Supplier로 필요 시점에 가져옵니다.
 */
public class TokenIssuingSuccessHandler implements AuthenticationSuccessHandler {
    private final Supplier<TokenService> tokenServiceSupplier;
    private final AuthenticationSuccessHandler delegate;

    public TokenIssuingSuccessHandler(Supplier<TokenService> tokenServiceSupplier,
                                      AuthenticationSuccessHandler delegate) {
        this.tokenServiceSupplier = tokenServiceSupplier;
        this.delegate             = delegate;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        TokenService tokenService = tokenServiceSupplier.get();
        String deviceId = request.getHeader("X-Device-Id");
        if (!StringUtils.hasText(deviceId)) {
            throw new BadCredentialsException("Device ID missing");
        }
        try {
            String access  = tokenService.createAccessToken(authentication, deviceId);
            String refresh = tokenService.createRefreshToken(authentication, deviceId);
            tokenService.writeAccessAndRefreshToken(response, access, refresh);
        } catch (Exception e) {
            throw new AuthenticationServiceException("Token issuance failed", e);
        }

        // 4) 원본 성공 핸들러 호출
//        delegate.onAuthenticationSuccess(request, response, authentication);
    }
}


