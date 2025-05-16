package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.http.JsonAuthResponseWriter;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomTokenIssuingSuccessHandler implements AuthenticationSuccessHandler, OneTimeTokenGenerationSuccessHandler {

    private final TokenService tokenService;
    private final ContextPersistence contextPersistence;
    private final AuthResponseWriter authResponseWriter;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {
        log.info("CustomTokenIssuingSuccessHandler: Standard authentication success for user {}", authentication.getName());
        issueTokensAndRespond(request, response, authentication);
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken oneTimeToken) throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            log.warn("CustomTokenIssuingSuccessHandler: OTT flow - Authentication not found in SecurityContext after OneTimeToken consumption. OTT User: {}", oneTimeToken.getUsername());
            // 이 경우, AuthResponseWriter를 사용하여 오류 응답을 보내는 것이 일관적일 수 있음.
            // 또는, MfaAuthenticationFailureHandler와 유사한 오류 처리기를 호출.
            // 여기서는 간단히 sendError로 처리.
            if (!response.isCommitted()) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Authentication context not established after OTT for CustomTokenIssuingSuccessHandler.");
            }
            return;
        }
        log.info("CustomTokenIssuingSuccessHandler: OTT authentication success for user {}", authentication.getName());
        issueTokensAndRespond(request, response, authentication);
    }

    private void issueTokensAndRespond(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        if (authentication == null || !authentication.isAuthenticated()) {
            log.warn("CustomTokenIssuingSuccessHandler: Authentication object is null or not authenticated. Cannot issue tokens.");
            // 적절한 오류 응답 (예: AuthResponseWriter 사용)
            if (!response.isCommitted()) {
                // 여기서 AuthResponseWriter를 직접 사용하거나, 예외를 던져 전역 핸들러가 처리하도록 함.
                // AuthResponseWriter responseWriter = new JsonAuthResponseWriter(tokenService.getObjectMapper()); // 임시 생성
                // responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "UNAUTHENTICATED", "Cannot issue tokens for unauthenticated user.", request.getRequestURI());
                throw new AuthenticationServiceException("Cannot issue tokens for unauthenticated user.");
            }
            return;
        }

        String deviceId = getEffectiveDeviceId(request);

        try {
            String accessToken = tokenService.createAccessToken(authentication, deviceId);
            String refreshTokenVal = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshTokenVal = tokenService.createRefreshToken(authentication, deviceId);
            }

            log.info("CustomTokenIssuingSuccessHandler: Issuing final tokens for user {} (Device ID: {})", authentication.getName(), deviceId);

            FactorContext factorContext = contextPersistence.contextLoad(request);
            if (factorContext != null) {
                log.debug("MFA flow likely completed. Clearing FactorContext for session: {}", factorContext.getMfaSessionId());
                contextPersistence.deleteContext(request);
            }

            // <<< 핵심: TokenService에 최종 토큰 전송 위임 >>>
            tokenService.writeAccessAndRefreshToken(response, accessToken, refreshTokenVal);
            // TokenService가 응답을 커밋하므로, 이 핸들러는 추가 응답 작성을 하지 않음.

        } catch (Exception e) {
            log.error("Token issuance failed in CustomTokenIssuingSuccessHandler for user {}: {}", authentication.getName(), e.getMessage(), e);
            if (!response.isCommitted()) {
                authResponseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "TOKEN_ISSUANCE_ERROR", "토큰 발급 중 오류가 발생했습니다: " + e.getMessage(), request.getRequestURI());
            }
        }
    }

    private String getEffectiveDeviceId(HttpServletRequest request) {
        String deviceId = request.getHeader("X-Device-Id");
        FactorContext factorContext = contextPersistence.contextLoad(request); // 실패 시 null일 수 있음

        if (factorContext != null && StringUtils.hasText((String) factorContext.getAttribute("deviceId"))) {
            deviceId = (String) factorContext.getAttribute("deviceId");
        } else if (!StringUtils.hasText(deviceId)) {
            HttpSession session = request.getSession(false); // 세션이 없을 수도 있음
            if (session != null) {
                deviceId = (String) session.getAttribute("sessionDeviceIdForAuth");
            }
            if (deviceId == null) { // 세션에도 없으면 새로 생성
                deviceId = UUID.randomUUID().toString();
                HttpSession newSession = request.getSession(true); // 이때 세션 생성
                newSession.setAttribute("sessionDeviceIdForAuth", deviceId);
            }
        }
        if (deviceId == null) { // 정말 모든 경우에 deviceId가 없다면 임시값 또는 오류
            log.warn("Device ID could not be determined. Generating a temporary one for token issuance.");
            deviceId = UUID.randomUUID().toString();
        }
        log.debug("Effective Device ID for token issuance: {}", deviceId);
        return deviceId;
    }

    // determineTargetUrl 메서드는 TokenService.writeAccessAndRefreshToken 내부에서 처리되거나,
    // TokenResponse에 포함된 redirectUrl을 클라이언트가 사용하므로 여기서는 불필요.
}

