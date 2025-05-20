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

        FactorContext mfaCtx = new FactorContext(authentication);
        String deviceId = getEffectiveDeviceId(request, mfaCtx);
        mfaCtx.setAttribute("deviceId", deviceId);

        // 수정된 부분: evaluateMfaPolicy 대신 evaluateMfaRequirementAndDetermineInitialStep 사용
        mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(authentication, mfaCtx);

        if (mfaCtx.isMfaRequiredAsPerPolicy()) { // isMfaRequired() -> isMfaRequiredAsPerPolicy()
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
            responseBody.put("status", "SUCCESS"); // 명시적 성공 상태 추가
            responseBody.put("message", "Authentication successful.");
            responseBody.put("redirectUrl", determineTargetUrl(request, response, authentication));
            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);

            contextPersistence.deleteContext(request);
        }
    }

    // getEffectiveDeviceId 메소드는 FactorContext를 파라미터로 받는 버전 유지
    private String getEffectiveDeviceId(HttpServletRequest request, FactorContext factorContext) {
        String deviceId = request.getHeader("X-Device-Id");
        // FactorContext가 null이 아니고, 해당 컨텍스트에 이미 deviceId가 있다면 그것을 사용
        if (factorContext != null && StringUtils.hasText((String) factorContext.getAttribute("deviceId"))) {
            deviceId = (String) factorContext.getAttribute("deviceId");
            log.debug("Using deviceId from provided FactorContext: {}", deviceId);
        } else if (!StringUtils.hasText(deviceId)) { // 요청 헤더에도 없고, FactorContext에도 없을 경우
            HttpSession session = request.getSession(true); // 세션이 없다면 생성
            deviceId = (String) session.getAttribute("sessionDeviceIdForAuth");
            if (deviceId == null) {
                deviceId = UUID.randomUUID().toString();
                session.setAttribute("sessionDeviceIdForAuth", deviceId);
                log.debug("Generated and stored new sessionDeviceIdForAuth: {}", deviceId);
            } else {
                log.debug("Using deviceId from sessionDeviceIdForAuth: {}", deviceId);
            }
        } else {
            log.debug("Using deviceId from request header 'X-Device-Id': {}", deviceId);
        }

        if (deviceId == null) { // 최종 fallback
            deviceId = UUID.randomUUID().toString();
            log.warn("No deviceId found from header, FactorContext, or session. Generated a new transient one: {}", deviceId);
        }
        // 사용자 이름을 로그에 남길 때, FactorContext가 null이 아닐 경우 해당 컨텍스트의 사용자 이름을 사용
        log.debug("Effective Device ID for {}: {}", (factorContext != null ? factorContext.getUsername() : "N/A"), deviceId);
        return deviceId;
    }

    // determineTargetUrl 메소드는 기존 로직 유지
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
        return this.defaultTargetUrl;
    }
}