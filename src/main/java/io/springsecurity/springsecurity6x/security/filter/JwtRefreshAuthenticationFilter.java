package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.exception.TokenInvalidException;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class JwtRefreshAuthenticationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final String refreshUri;
    private final LogoutHandler logoutHandler;
    private final AuthResponseWriter responseWriter;

    public JwtRefreshAuthenticationFilter(TokenService tokenService,
                                          LogoutHandler logoutHandler,
                                          AuthResponseWriter responseWriter) { // AuthResponseWriter 주입
        this.tokenService = tokenService;
        if (tokenService.properties() == null || tokenService.properties().getInternal() == null || tokenService.properties().getInternal().getRefreshUri() == null) {
            throw new IllegalArgumentException("Refresh URI cannot be determined from tokenService properties.");
        }
        this.refreshUri = tokenService.properties().getInternal().getRefreshUri();
        this.logoutHandler = logoutHandler;
        this.responseWriter = responseWriter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        if (!refreshUri.equals(request.getRequestURI())) {
            chain.doFilter(request, response);
            return;
        }
        log.debug("JwtRefreshAuthenticationFilter processing request for: {}", request.getRequestURI());

        String refreshTokenFromRequest = tokenService.resolveRefreshToken(request);

        if (StringUtils.hasText(refreshTokenFromRequest)) {
            try {
                log.debug("Attempting to refresh token.");

                TokenService.RefreshResult result = tokenService.refresh(refreshTokenFromRequest);
                tokenService.writeAccessAndRefreshToken(response, result.accessToken(), result.refreshToken());

                log.info("Token refreshed successfully and written to response by TokenService.");

            } catch (TokenInvalidException tie) {
                log.warn("Invalid refresh token provided: {}", tie.getMessage());
                handleLogoutAndErrorResponse(request, response, HttpServletResponse.SC_UNAUTHORIZED, "invalid_refresh_token", "리프레시 토큰이 유효하지 않거나 만료되었습니다: " + tie.getMessage());

            } catch (Exception e) {
                log.error("Error during token refresh: {}", e.getMessage(), e);
                handleLogoutAndErrorResponse(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "token_refresh_error", "토큰 리프레시 중 서버 오류가 발생했습니다.");
            }
        } else {
            log.warn("No refresh token found in request to {}", refreshUri);
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "missing_refresh_token", "요청에 리프레시 토큰이 없습니다.", request.getRequestURI());
        }
    }

    /**
     * 리프레시 실패 시 로그아웃 처리(선택적) 후 JSON 오류 응답을 보냅니다.
     */
    private void handleLogoutAndErrorResponse(HttpServletRequest request, HttpServletResponse response, int status, String errorCode, String errorMessage) throws IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && logoutHandler != null) {
            try {
                logoutHandler.logout(request, response, auth);
            } catch (Exception logoutEx) {
                log.warn("Exception during logout_handler execution after refresh failure: {}", logoutEx.getMessage());
            }
        }
        if (!response.isCommitted()) {
            responseWriter.writeErrorResponse(response, status, errorCode, errorMessage, request.getRequestURI());
        } else {
            log.warn("Response already committed after logoutHandler. Cannot write error JSON for refresh failure. Status: {}, Error: {}", status, errorCode);
        }
    }
}

