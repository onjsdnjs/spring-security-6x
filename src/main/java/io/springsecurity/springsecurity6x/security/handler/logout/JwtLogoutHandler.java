package io.springsecurity.springsecurity6x.security.handler.logout;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.store.TokenInfo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import java.util.Objects;

public class JwtLogoutHandler implements LogoutHandler {

    private static final Logger log = LoggerFactory.getLogger(JwtLogoutHandler.class);
    private final TokenService tokenService;

    public JwtLogoutHandler(TokenService tokenService) {
        this.tokenService = Objects.requireNonNull(tokenService, "tokenService cannot be null");
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String refreshToken = tokenService.resolveRefreshToken(request);
        String username = (authentication != null) ? authentication.getName() : "UNKNOWN_USER_LOGOUT";

        try {
            if (refreshToken != null) {
                log.debug("Attempting to invalidate and blacklist refresh token for user: {}", username);
                tokenService.invalidateRefreshToken(refreshToken);
                tokenService.blacklistRefreshToken(refreshToken, username, TokenInfo.REASON_LOGOUT);
                log.info("Successfully invalidated and blacklisted refresh token for user: {}", username);
            } else {
                log.debug("No refresh token found in request for user: {}", username);
            }
        } catch (AuthenticationException ex) {
            log.warn("AuthenticationException during logout for user {}: {}", username, ex.getMessage());
            SecurityContextHolder.clearContext(); // 컨텍스트는 비움
            // 이 예외를 그대로 전파하면 Global Exception Handler 또는 Spring Security의 EntryPoint가 처리
            throw ex;
        } catch (Exception ex) {
            log.error("Unexpected error during refresh token invalidation/blacklisting for user {}: {}", username, ex.getMessage(), ex);
            SecurityContextHolder.clearContext();
            // 일반 Exception의 경우, 어떻게 처리할지 정책 필요.
            // 여기서는 AuthenticationServiceException 으로 감싸서 전파하는 것을 고려할 수 있으나,
            // 이미 로그아웃 처리 중이므로 클라이언트에 오류 응답을 직접 보내는 것이 나을 수 있음.
            // 단, clearTokens 에서 응답을 이미 커밋할 수 있으므로 주의.
        } finally {
            // 응답이 아직 커밋되지 않았다면 토큰 정리 및 SecurityContext 클리어
            if (!response.isCommitted()) {
                tokenService.clearTokens(response); // 이 메소드가 응답을 커밋할 수 있음
            }
            SecurityContextHolder.clearContext();
            log.debug("SecurityContext cleared for user: {}", username);
        }
    }
}

