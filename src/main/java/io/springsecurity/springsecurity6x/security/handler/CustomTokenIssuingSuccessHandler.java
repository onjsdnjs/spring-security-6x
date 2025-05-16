package io.springsecurity.springsecurity6x.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
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
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component // 스프링 빈으로 관리
@RequiredArgsConstructor
public class CustomTokenIssuingSuccessHandler implements AuthenticationSuccessHandler, OneTimeTokenGenerationSuccessHandler {

    private final TokenService tokenService;
    private final ContextPersistence contextPersistence;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException{

        log.info("CustomTokenIssuingSuccessHandler: Standard authentication success for user {}", authentication.getName());
        issueTokensAndRespond(request, response, authentication);
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken oneTimeToken) throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContextHolderStrategy().getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            // OTT 인증 후 SecurityContext에 Authentication 객체가 없을 경우 처리
            // (예: OneTimeTokenAuthenticationFilter 에서 SecurityContext에 인증 객체를 설정해야 함)
            log.warn("CustomTokenIssuingSuccessHandler: OTT flow - Authentication not found in SecurityContext after OneTimeToken consumption. OTT User: {}", oneTimeToken.getUsername());
            // 이 경우, oneTimeToken.getUsername() 등을 기반으로 Authentication 객체를 생성하거나, 오류 처리 필요.
            // 간단히 에러 처리하거나, UsernamePasswordAuthenticationToken 등을 임시로 만들 수 있음.
            // 여기서는 오류로 간주하고 중단. 실제 구현 시 정책에 따라 변경.
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Authentication context not established after OTT.");
            return;
        }
        log.info("CustomTokenIssuingSuccessHandler: OTT authentication success for user {}", authentication.getName());
        issueTokensAndRespond(request, response, authentication);
    }

    private void issueTokensAndRespond(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        if (authentication == null || !authentication.isAuthenticated()) {
            log.warn("TokenIssuingHandler: Authentication object is null or not authenticated. Cannot issue tokens.");
            throw new AuthenticationServiceException("Cannot issue tokens for unauthenticated user.");
        }

        String deviceId = getEffectiveDeviceId(request);

        try {
            String accessToken = tokenService.createAccessToken(authentication, deviceId);
            String refreshTokenVal = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshTokenVal = tokenService.createRefreshToken(authentication, deviceId);
            }

            log.info("Issuing tokens for user {} (Device ID: {})", authentication.getName(), deviceId);

            FactorContext factorContext = contextPersistence.contextLoad(request);
            if (factorContext != null) {
                log.debug("MFA flow likely completed or bypassed. Clearing FactorContext for session: {}", factorContext.getMfaSessionId());
                contextPersistence.deleteContext(request);
            }

            Map<String, Object> tokenResponse = new HashMap<>();
            tokenResponse.put("status", "SUCCESS");
            tokenResponse.put("message", "인증 성공 및 토큰 발급 완료.");
            tokenResponse.put("accessToken", accessToken);
            if (refreshTokenVal != null) {
                tokenResponse.put("refreshToken", refreshTokenVal);
            }
            tokenResponse.put("redirectUrl", determineTargetUrl(request, authentication, "/"));

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json;charset=UTF-8");
            objectMapper.writeValue(response.getWriter(), tokenResponse);

        } catch (Exception e) {
            log.error("Token issuance failed for user {}: {}", authentication.getName(), e.getMessage(), e);
            // ... (기존 오류 처리 로직)
            if (!response.isCommitted()) {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.setContentType("application/json;charset=UTF-8");
                objectMapper.writeValue(response.getWriter(), Map.of("error", "TOKEN_ISSUANCE_ERROR", "message", "토큰 발급 중 오류가 발생했습니다: " + e.getMessage()));
            }
        }
    }

    private String getEffectiveDeviceId(HttpServletRequest request) {
        String deviceId = request.getHeader("X-Device-Id");
        FactorContext factorContext = contextPersistence.contextLoad(request);

        if (factorContext != null && StringUtils.hasText((String) factorContext.getAttribute("deviceId"))) {
            deviceId = (String) factorContext.getAttribute("deviceId");
            log.debug("Using deviceId from FactorContext: {}", deviceId);
        } else if (StringUtils.hasText(deviceId)) {
            log.debug("Using deviceId from request header: {}", deviceId);
        } else {
            HttpSession session = request.getSession(true);
            deviceId = (String) session.getAttribute("sessionDeviceIdForAuth");
            if (deviceId == null) {
                deviceId = UUID.randomUUID().toString();
                session.setAttribute("sessionDeviceIdForAuth", deviceId);
                log.debug("Generated new session-based deviceId: {}", deviceId);
            } else {
                log.debug("Using deviceId from session attribute: {}", deviceId);
            }
        }
        return deviceId;
    }

    protected String determineTargetUrl(HttpServletRequest request, Authentication authentication, String defaultUrl) {
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


