package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportResult;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomTokenIssuingSuccessHandler implements AuthenticationSuccessHandler, OneTimeTokenGenerationSuccessHandler {

    private final TokenService tokenService;
    private final ContextPersistence contextPersistence;
    private final AuthResponseWriter responseWriter; // 추가 (실패 시 또는 redirectUrl 응답 시 사용)
    private final String defaultTargetUrl = "/"; // 기본 리다이렉트 URL

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {
        log.info("CustomTokenIssuingSuccessHandler: Standard authentication success for user {}", authentication.getName());
        issueTokensAndRespond(request, response, authentication);
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken oneTimeToken) throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContextHolderStrategy().getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            String usernameFromToken = (oneTimeToken != null && oneTimeToken.getUsername() != null) ? oneTimeToken.getUsername() : "Unknown OTT User";
            log.warn("CustomTokenIssuingSuccessHandler: OTT flow - Authentication not found in SecurityContext after OneTimeToken consumption. OTT User: {}", usernameFromToken);
            if (!response.isCommitted()) {
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "AUTH_CONTEXT_MISSING_OTT_CUSTOM", "Authentication context missing after OTT.", request.getRequestURI());
            }
            return;
        }
        log.info("CustomTokenIssuingSuccessHandler: OTT authentication success for user {}", authentication.getName());
        issueTokensAndRespond(request, response, authentication);
    }

    private void issueTokensAndRespond(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        if (authentication == null || !authentication.isAuthenticated()) {
            log.warn("CustomTokenIssuingSuccessHandler: Authentication object is null or not authenticated. Cannot issue tokens.");
            if (!response.isCommitted()) {
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "UNAUTHENTICATED", "Cannot issue tokens for unauthenticated user.", request.getRequestURI());
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
                log.debug("Clearing FactorContext for session: {}", factorContext.getMfaSessionId());
                contextPersistence.deleteContext(request);
            }

            TokenTransportResult transportResult = tokenService.prepareTokensForTransport(accessToken, refreshTokenVal);

            if (transportResult.getCookiesToSet() != null) {
                for (ResponseCookie cookie : transportResult.getCookiesToSet()) {
                    response.addHeader("Set-Cookie", cookie.toString());
                }
            }
            // TokenResponse에 redirectUrl이 이미 포함되어 있다고 가정하고,
            // AuthResponseWriter가 이를 클라이언트에 전달하도록 함.
            // 만약 TokenResponse에 redirectUrl이 없다면, 여기서 Map에 추가.
            Map<String, Object> responseBody = new HashMap<>(transportResult.getBody());
            if (!responseBody.containsKey("redirectUrl")) {
                responseBody.put("redirectUrl", determineTargetUrl(request, authentication, this.defaultTargetUrl));
            }
            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);

        } catch (Exception e) {
            log.error("Token issuance failed in CustomTokenIssuingSuccessHandler for user {}: {}", authentication.getName(), e.getMessage(), e);
            if (!response.isCommitted()) {
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "TOKEN_ISSUANCE_ERROR_CUSTOM", "토큰 발급 중 오류가 발생했습니다: " + e.getMessage(), request.getRequestURI());
            }
        }
    }

    private String getEffectiveDeviceId(HttpServletRequest request) { /* ... 이전과 동일 ... */
        String deviceId = request.getHeader("X-Device-Id");
        FactorContext factorContext = contextPersistence.contextLoad(request);

        if (factorContext != null && StringUtils.hasText((String) factorContext.getAttribute("deviceId"))) {
            deviceId = (String) factorContext.getAttribute("deviceId");
        } else if (!StringUtils.hasText(deviceId)) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                deviceId = (String) session.getAttribute("sessionDeviceIdForAuth");
            }
            if (deviceId == null) {
                HttpSession newSession = request.getSession(true);
                deviceId = UUID.randomUUID().toString();
                newSession.setAttribute("sessionDeviceIdForAuth", deviceId);
            }
        }
        if (deviceId == null) deviceId = UUID.randomUUID().toString();
        log.debug("Effective Device ID for token issuance in CustomHandler: {}", deviceId);
        return deviceId;
    }

    protected String determineTargetUrl(HttpServletRequest request, Authentication authentication, String defaultUrl) { /* ... 이전과 동일 ... */
        HttpSession session = request.getSession(false);
        if (session != null) {
            org.springframework.security.web.savedrequest.SavedRequest savedRequest =
                    (org.springframework.security.web.savedrequest.SavedRequest) session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
            if (savedRequest != null) {
                session.removeAttribute("SPRING_SECURITY_SAVED_REQUEST");
                return savedRequest.getRedirectUrl();
            }
        }
        return defaultUrl;
    }
}

