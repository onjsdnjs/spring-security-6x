package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.exception.TokenInvalidException;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

@Slf4j
public class JwtRefreshAuthenticationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final String refreshUri;
    private final LogoutHandler logoutHandler;
    private final AuthResponseWriter responseWriter;

    public JwtRefreshAuthenticationFilter(TokenService tokenService, LogoutHandler logoutHandler, AuthResponseWriter responseWriter) { // AuthResponseWriter 주입
        this.tokenService = tokenService;
        if (tokenService.properties() == null || tokenService.properties().getInternal() == null || tokenService.properties().getInternal().getRefreshUri() == null) {
            throw new IllegalArgumentException("Refresh URI cannot be determined from tokenService properties.");
        }
        this.refreshUri = tokenService.properties().getInternal().getRefreshUri();
        this.logoutHandler = logoutHandler;
        this.responseWriter = responseWriter; // 주입
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

                // 성공 시: TokenService의 writeAccessAndRefreshToken를 사용하거나, 여기서 직접 AuthResponseWriter 사용
                // TokenTransportStrategy 내에서도 AuthResponseWriter를 사용하도록 변경 가능
                // 현재 TokenService.writeAccessAndRefreshToken는 내부적으로 transport.writeJson을 사용하므로,
                // 그 부분을 AuthResponseWriter를 사용하도록 리팩토링하거나, 여기서 직접 호출.
                // 여기서는 직접 호출 예시:
                Map<String, Object> successData = Map.of(
                        "accessToken", result.accessToken(),
                        "refreshToken", result.refreshToken(), // HeaderTokenStrategy의 경우
                        "tokenType", "Bearer",
                        "expiresIn", tokenService.properties().getAccessTokenValidity()
                );
                // 만약 HeaderCookieTokenStrategy 라면 refreshToken은 본문에 포함하지 않음
                // if (tokenService.properties().getTokenTransportType() == TokenTransportType.HEADER_COOKIE) {
                //    ((Map<String, Object>)successData).put("refreshToken", null); // 예시
                // }
                responseWriter.writeSuccessResponse(response, successData);
                log.info("Token refreshed successfully.");
                return;

            } catch (TokenInvalidException tie) {
                log.warn("Invalid refresh token provided: {}", tie.getMessage());
                // logoutHandler.logout(...) 호출은 여기서 제거하거나, logoutHandler가 응답을 커밋하지 않도록 보장 필요.
                // 리프레시 실패 시 자동 로그아웃이 정책이라면, logoutHandler는 호출하되 응답은 responseWriter가 담당.
                // Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                // if (auth != null && logoutHandler != null) logoutHandler.logout(request, response, auth);
                // if (!response.isCommitted()) {
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "invalid_refresh_token", "리프레시 토큰이 유효하지 않거나 만료되었습니다: " + tie.getMessage(), request.getRequestURI());
                // }
                return;
            } catch (Exception e) {
                log.error("Error during token refresh: {}", e.getMessage(), e);
                // Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                // if (auth != null && logoutHandler != null) logoutHandler.logout(request, response, auth);
                // if (!response.isCommitted()) {
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "token_refresh_error", "토큰 리프레시 중 서버 오류가 발생했습니다.", request.getRequestURI());
                // }
                return;
            }
        } else {
            log.warn("No refresh token found in request to {}", refreshUri);
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "missing_refresh_token", "요청에 리프레시 토큰이 없습니다.", request.getRequestURI());
            return;
        }
    }
}

