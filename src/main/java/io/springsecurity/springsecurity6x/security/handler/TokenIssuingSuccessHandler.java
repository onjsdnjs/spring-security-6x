package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.function.Supplier;

/**
 * TokenService를 직접 들고 있지 않고, Supplier로 필요 시점에 가져옵니다.
 */
public class TokenIssuingSuccessHandler implements AuthenticationSuccessHandler, OneTimeTokenGenerationSuccessHandler {
    private final Supplier<TokenService> tokenServiceSupplier;
    private AuthenticationSuccessHandler successHandler;
    private OneTimeTokenGenerationSuccessHandler ottSuccessHandler;

    public TokenIssuingSuccessHandler(Supplier<TokenService> tokenServiceSupplier,
                                      AuthenticationSuccessHandler successHandler) {
        this.tokenServiceSupplier = tokenServiceSupplier;
        this.successHandler             = successHandler;
    }

    public TokenIssuingSuccessHandler(Supplier<TokenService> tokenServiceSupplier,
                                      OneTimeTokenGenerationSuccessHandler ottSuccessHandler) {
        this.tokenServiceSupplier = tokenServiceSupplier;
        this.ottSuccessHandler             = ottSuccessHandler;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        tokenService(request, response, authentication);
        // 4) 원본 성공 핸들러 호출
//        delegate.onAuthenticationSuccess(request, response, authentication);
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken oneTimeToken) throws IOException, ServletException {
        SecurityContext context = SecurityContextHolder.getContextHolderStrategy().getContext();
        tokenService(request, response, context.getAuthentication());
    }

    private void tokenService(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
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
    }
}


