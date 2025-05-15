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
@Component // Spring Bean으로 등록
@RequiredArgsConstructor
public class CustomTokenIssuingSuccessHandler implements AuthenticationSuccessHandler, OneTimeTokenGenerationSuccessHandler {

    private final TokenService tokenService; // 직접 주입
    private final ContextPersistence contextPersistence; // MFA 컨텍스트 정리용
    private final ObjectMapper objectMapper; // JSON 응답용

    // 일반 인증 성공 시 (Form, REST 1차 (MFA 불필요 시), 단일 Passkey 등)
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        log.info("CustomTokenIssuingSuccessHandler: Standard authentication success for user {}", authentication.getName());
        issueTokensAndRespond(request, response, authentication);
    }

    // OTT 인증 성공 시 (단일 OTT, 또는 MFA의 OTT 단계 완료 후 최종 토큰 발급 시)
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken oneTimeToken) throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContextHolderStrategy().getContext().getAuthentication();
        log.info("CustomTokenIssuingSuccessHandler: OTT authentication success for user {}", authentication.getName());
        issueTokensAndRespond(request, response, authentication);
    }

    /**
     * 공통 토큰 발급 및 응답 처리 로직.
     * API 요청(Accept: application/json)에는 JSON으로 토큰을 반환하고,
     * 그 외의 경우 (예: 전통적인 Form 로그인 후)에는 기본 성공 URL로 리다이렉션합니다.
     * (단, 이 프로젝트는 주로 API 기반 JWT 인증이므로 JSON 응답이 주가 됩니다.)
     */
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

            // MFA 컨텍스트가 있었다면 성공 후 삭제
            FactorContext factorContext = contextPersistence.contextLoad(request);
            if (factorContext != null) {
                log.debug("MFA flow likely completed or bypassed. Clearing FactorContext for session: {}", factorContext.getMfaSessionId());
                contextPersistence.deleteContext(request);
            }

            // TokenTransportStrategy는 JSON 응답 시에는 직접 사용하지 않고,
            // 응답 본문에 토큰을 담아 전달. 쿠키 방식일 경우 transport.writeAccessAndRefreshToken 사용.
            // 여기서는 API 중심이므로 JSON 응답을 기본으로 함.
            Map<String, Object> tokenResponse = new HashMap<>();
            tokenResponse.put("status", "SUCCESS");
            tokenResponse.put("message", "인증 성공 및 토큰 발급 완료.");
            tokenResponse.put("accessToken", accessToken);
            if (refreshTokenVal != null) {
                tokenResponse.put("refreshToken", refreshTokenVal);
            }
            tokenResponse.put("redirectUrl", determineTargetUrl(request, authentication, "/")); // 성공 시 기본 리다이렉트 URL

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json;charset=UTF-8");
            objectMapper.writeValue(response.getWriter(), tokenResponse);

        } catch (Exception e) {
            log.error("Token issuance failed for user {}: {}", authentication.getName(), e.getMessage(), e);
            if (!response.isCommitted()) {
                try {
                    objectMapper.writeValue(response.getWriter(), Map.of("error", "TOKEN_ISSUANCE_ERROR", "message", "토큰 발급 중 오류가 발생했습니다."));
                    response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                    response.setContentType("application/json;charset=UTF-8");
                } catch (IOException ex) {
                    log.error("Error writing error response for token issuance failure", ex);
                }
            }
            // AuthenticationServiceException을 그대로 던지면 Spring Security의 ExceptionTranslationFilter가 처리할 수 있음.
            // throw new AuthenticationServiceException("Token issuance failed", e);
        }
    }

    private String getEffectiveDeviceId(HttpServletRequest request) {
        String deviceId = request.getHeader("X-Device-Id");
        FactorContext factorContext = contextPersistence.contextLoad(request); // 먼저 로드 시도

        if (factorContext != null && StringUtils.hasText((String) factorContext.getAttribute("deviceId"))) {
            deviceId = (String) factorContext.getAttribute("deviceId");
            log.debug("Using deviceId from FactorContext: {}", deviceId);
        } else if (StringUtils.hasText(deviceId)) {
            log.debug("Using deviceId from request header: {}", deviceId);
        } else {
            HttpSession session = request.getSession(true); // 세션이 없으면 생성
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
        // SavedRequest가 있으면 그곳으로, 아니면 defaultUrl
        HttpSession session = request.getSession(false);
        if (session != null) {
            org.springframework.security.web.savedrequest.SavedRequest savedRequest =
                    (org.springframework.security.web.savedrequest.SavedRequest) session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
            if (savedRequest != null) {
                session.removeAttribute("SPRING_SECURITY_SAVED_REQUEST"); // 사용 후 제거
                return savedRequest.getRedirectUrl();
            }
        }
        return defaultUrl;
    }
}


