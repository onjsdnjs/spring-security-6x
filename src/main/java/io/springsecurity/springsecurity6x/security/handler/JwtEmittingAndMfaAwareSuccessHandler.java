package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.repository.UserRepository;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
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
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
public class JwtEmittingAndMfaAwareSuccessHandler implements AuthenticationSuccessHandler, OneTimeTokenGenerationSuccessHandler {

    private final TokenService tokenService;
    private final String defaultTargetUrl;
    private final UserRepository userRepository;
    private final ContextPersistence contextPersistence;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;
    private final MfaPolicyProvider mfaPolicyProvider; // 추가: MfaPolicyProvider 주입 (MfaCapableRestSuccessHandler와 일관성)

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.debug("JwtEmittingAndMfaAwareSuccessHandler.onAuthenticationSuccess called for user: {}", authentication.getName());
        processAuthSuccess(request, response, authentication);
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken token) throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            String usernameFromToken = (token != null && token.getUsername() != null) ? token.getUsername() : "Unknown OTT User";
            log.warn("JwtEmittingAndMfaAwareSuccessHandler.handle (OTT): Authentication not found in SecurityContext for user from token: {}.", usernameFromToken);
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "AUTH_CONTEXT_MISSING_OTT_JWT_EMIT", "Authentication context missing after OTT.", request.getRequestURI());
            return;
        }
        log.debug("JwtEmittingAndMfaAwareSuccessHandler.handle (OTT) called for authenticated user: {} with OTT for: {}", authentication.getName(), token.getUsername());
        processAuthSuccess(request, response, authentication);
    }

    private void processAuthSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String username = authentication.getName();
        log.info("Processing auth success for user: {}. Checking MFA status.", username);

        Users user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        // MfaCapableRestSuccessHandler와 동일한 로직으로 MFA 필요 여부 판단 및 FactorContext 생성
        FactorContext mfaCtx = new FactorContext(authentication);
        String deviceId = getEffectiveDeviceId(request, mfaCtx); // deviceId 먼저 결정
        mfaCtx.setAttribute("deviceId", deviceId);
        mfaPolicyProvider.evaluateMfaPolicy(mfaCtx); // MfaPolicyProvider 사용

        if (mfaCtx.isMfaRequired()) {
            log.info("MFA is required for user: {}. Initiating MFA flow.", username);
            contextPersistence.saveContext(mfaCtx, request);

            Map<String, Object> mfaRequiredDetails = new HashMap<>();
            mfaRequiredDetails.put("status", "MFA_REQUIRED");
            mfaRequiredDetails.put("message", "1차 인증 성공. 2차 인증이 필요합니다.");
            mfaRequiredDetails.put("mfaSessionId", mfaCtx.getMfaSessionId());
            mfaRequiredDetails.put("nextStepUrl", authContextProperties.getMfa().getInitiateUrl());
            responseWriter.writeSuccessResponse(response, mfaRequiredDetails, HttpServletResponse.SC_OK);

        } else {
            log.info("MFA is not required for user: {}. Issuing tokens directly.", username);
            // deviceId는 위에서 이미 결정됨
            String accessToken = tokenService.createAccessToken(authentication, deviceId);
            String refreshToken = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshToken = tokenService.createRefreshToken(authentication, deviceId);
            }

            TokenTransportResult transportResult = tokenService.prepareTokensForTransport(accessToken, refreshToken);
            if (transportResult.getCookiesToSet() != null) {
                for (ResponseCookie cookie : transportResult.getCookiesToSet()) {
                    response.addHeader("Set-Cookie", cookie.toString());
                }
            }
            Map<String, Object> responseBody = new HashMap<>(transportResult.getBody());
            // 단일 인증 성공 시 redirectUrl을 포함하도록 확장 (선택적)
            responseBody.put("redirectUrl", determineTargetUrl(request, response, authentication));
            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);

            contextPersistence.deleteContext(request);
        }
    }

    private String getEffectiveDeviceId(HttpServletRequest request, FactorContext factorContext) { /* ... 이전 MfaCapableRestSuccessHandler와 동일 ... */
        String deviceId = request.getHeader("X-Device-Id");
        if (factorContext != null && StringUtils.hasText((String) factorContext.getAttribute("deviceId"))) {
            deviceId = (String) factorContext.getAttribute("deviceId");
        } else if (!StringUtils.hasText(deviceId)) {
            HttpSession session = request.getSession(true);
            deviceId = (String) session.getAttribute("sessionDeviceIdForAuth");
            if (deviceId == null) {
                deviceId = UUID.randomUUID().toString();
                session.setAttribute("sessionDeviceIdForAuth", deviceId);
            }
        }
        if (deviceId == null) deviceId = UUID.randomUUID().toString(); // 최종 fallback
        log.debug("Effective Device ID for {}: {}", (factorContext != null ? factorContext.getUsername() : "N/A"), deviceId);
        return deviceId;
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            org.springframework.security.web.savedrequest.SavedRequest savedRequest =
                    (org.springframework.security.web.savedrequest.SavedRequest) session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
            if (savedRequest != null) {
                session.removeAttribute("SPRING_SECURITY_SAVED_REQUEST");
                return savedRequest.getRedirectUrl();
            }
        }
        return this.defaultTargetUrl; // 생성자에서 주입받은 기본 URL
    }
}