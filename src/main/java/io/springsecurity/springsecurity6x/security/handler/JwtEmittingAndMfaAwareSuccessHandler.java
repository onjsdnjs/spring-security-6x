package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.repository.UserRepository;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
    private final String defaultTargetUrl; // 기본 성공 URL
    private final UserRepository userRepository;
    private final ContextPersistence contextPersistence;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter; // 추가

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
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "AUTH_CONTEXT_MISSING_OTT", "Authentication context not established after OTT.", request.getRequestURI());
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

        if (user.isMfaEnabled()) {
            log.info("MFA is required for user: {}. Initiating MFA flow.", username);
            FactorContext mfaCtx = new FactorContext(authentication);
            String deviceId = getEffectiveDeviceId(request, mfaCtx);
            mfaCtx.setAttribute("deviceId", deviceId);

            // MfaPolicyProvider를 여기서 직접 호출하거나 (Bean 주입 필요),
            // 이 핸들러가 MfaPolicyProvider를 모른다면, 기본 상태로 FactorContext를 시작.
            // 여기서는 MfaCapableRestSuccessHandler와 유사하게 로직을 가져오거나,
            // MfaPolicyProvider.evaluateMfaPolicy(mfaCtx); 호출 (MfaPolicyProvider 주입 필요)
            // 여기서는 간단히 상태 설정 후 저장
            if (!mfaCtx.getRegisteredMfaFactors().isEmpty() || mfaCtx.getPreferredAutoAttemptFactor() != null ) {
                mfaCtx.changeState(MfaState.AWAITING_MFA_FACTOR_SELECTION);
            } else {
                log.warn("User {} requires MFA but has no registered factors. MFA cannot proceed. This should be handled by MfaPolicyProvider.", username);
                // 이 경우, 사용자에게 오류를 알리거나, MFA를 우회하고 토큰을 발급할지 정책 결정 필요.
                // 여기서는 MFA 안내 JSON을 보내지만, 실제로는 Factor 선택이 불가능할 수 있음.
            }
            contextPersistence.saveContext(mfaCtx, request);

            Map<String, Object> mfaRequiredDetails = new HashMap<>();
            mfaRequiredDetails.put("status", "MFA_REQUIRED");
            mfaRequiredDetails.put("message", "1차 인증 성공. 2차 인증이 필요합니다.");
            mfaRequiredDetails.put("mfaSessionId", mfaCtx.getMfaSessionId());
            mfaRequiredDetails.put("nextStepUrl", authContextProperties.getMfa().getInitiateUrl());

            // MFA 안내는 AuthResponseWriter 사용
            responseWriter.writeSuccessResponse(response, mfaRequiredDetails, HttpServletResponse.SC_OK); // 200 OK와 함께 JSON

        } else {
            log.info("MFA is not required for user: {}. Issuing tokens directly via TokenService.", username);
            String deviceId = getEffectiveDeviceId(request, null);

            String accessToken = tokenService.createAccessToken(authentication, deviceId);
            String refreshToken = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshToken = tokenService.createRefreshToken(authentication, deviceId);
            }

            // <<< 핵심: TokenService에 토큰 전송 위임 >>>
            tokenService.writeAccessAndRefreshToken(response, accessToken, refreshToken);

            // 단일 인증 성공 시 FactorContext가 남아있을 이유가 없으므로 삭제
            contextPersistence.deleteContext(request);
        }
    }

    private String getEffectiveDeviceId(HttpServletRequest request, FactorContext factorContext) {
        String deviceId = request.getHeader("X-Device-Id");
        if (factorContext != null && StringUtils.hasText((String) factorContext.getAttribute("deviceId"))) {
            deviceId = (String) factorContext.getAttribute("deviceId");
        } else if (!StringUtils.hasText(deviceId)) {
            HttpSession session = request.getSession(true); // 세션이 없으면 생성
            deviceId = (String) session.getAttribute("sessionDeviceIdForAuth");
            if (deviceId == null) {
                deviceId = UUID.randomUUID().toString();
                session.setAttribute("sessionDeviceIdForAuth", deviceId);
            }
        }
        log.debug("Effective Device ID for {}: {}", (factorContext != null ? factorContext.getUsername() : "N/A"), deviceId);
        return deviceId;
    }

    // determineTargetUrl 메서드는 CustomTokenIssuingSuccessHandler에 이미 있으므로,
    // 이 핸들러가 리다이렉션 정보를 직접 포함하지 않는다면 제거해도 됨.
    // 만약 TokenService.writeAccessAndRefreshToken 내부에서 리다이렉트 정보를 포함하지 않는다면 여기서 추가.
    // 현재 TokenResponse에는 redirectUrl이 있으므로, TokenService.writeAccessAndRefreshToken에서
    // 해당 정보를 활용하여 JSON에 포함시켜야 함.
}