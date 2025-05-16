package io.springsecurity.springsecurity6x.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.repository.UserRepository;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor // 생성자 주입을 위해
public class JwtEmittingAndMfaAwareSuccessHandler implements AuthenticationSuccessHandler {

    private final TokenService tokenService;
    private final ObjectMapper objectMapper;
    private final String defaultTargetUrl;
    private final UserRepository userRepository; // MFA 여부 확인용
    private final ContextPersistence contextPersistence; // MFA 컨텍스트 저장용
    private final AuthContextProperties authContextProperties; // MFA 시작 URL 가져오기용

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String username = authentication.getName();
        log.info("Single Authentication successful for user: {}. Checking MFA status.", username);

        Users user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        if (user.isMfaEnabled()) {
            log.info("MFA is required for user: {}. Initiating MFA flow.", username);
            FactorContext mfaCtx = new FactorContext(authentication); // 새로운 FactorContext 생성
            String deviceId = getEffectiveDeviceId(request, mfaCtx); // Device ID 설정 (필요시)
            mfaCtx.setAttribute("deviceId", deviceId);
            // mfaPolicyProvider.evaluateMfaPolicy(mfaCtx); // 만약 MfaPolicyProvider를 사용한다면 여기서 정책 평가
            // 여기서는 간단히 isMfaEnabled()만 확인

            contextPersistence.saveContext(mfaCtx, request); // MFA 컨텍스트 저장

            Map<String, Object> mfaRequiredResponse = new HashMap<>();
            mfaRequiredResponse.put("status", "MFA_REQUIRED");
            mfaRequiredResponse.put("message", "1차 인증 성공. 2차 인증이 필요합니다.");
            mfaRequiredResponse.put("mfaSessionId", mfaCtx.getMfaSessionId());
            mfaRequiredResponse.put("nextStepUrl", authContextProperties.getMfa().getInitiateUrl()); // 예: /mfa/select-factor

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json;charset=UTF-8");
            objectMapper.writeValue(response.getWriter(), mfaRequiredResponse);
            return; // MFA 흐름으로 전환하므로 여기서 응답 종료
        }

        // MFA가 필요 없는 경우, 기존처럼 토큰 발급
        log.info("MFA is not required for user: {}. Issuing tokens directly.", username);
        String deviceId = getEffectiveDeviceId(request, null);

        String accessToken = tokenService.createAccessToken(authentication, deviceId);
        String refreshToken = null;
        if (tokenService.properties().isEnableRefreshToken()) {
            refreshToken = tokenService.createRefreshToken(authentication, deviceId);
        }

        Map<String, Object> tokenResponse = new HashMap<>();
        tokenResponse.put("status", "SUCCESS");
        tokenResponse.put("message", "로그인 성공");
        tokenResponse.put("accessToken", accessToken);
        if (refreshToken != null) tokenResponse.put("refreshToken", refreshToken);
        tokenResponse.put("redirectUrl", determineTargetUrl(request, response, authentication));

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json;charset=UTF-8");
        objectMapper.writeValue(response.getWriter(), tokenResponse);
    }

    // getEffectiveDeviceId, determineTargetUrl 메소드는 이전과 동일하게 유지
    private String getEffectiveDeviceId(HttpServletRequest request, FactorContext factorContext) {
        String deviceId = request.getHeader("X-Device-Id");

        if (factorContext != null && org.springframework.util.StringUtils.hasText((String) factorContext.getAttribute("deviceId"))) {
            deviceId = (String) factorContext.getAttribute("deviceId");
            log.debug("Using deviceId from FactorContext: {}", deviceId);
        } else if (org.springframework.util.StringUtils.hasText(deviceId)) {
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

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            org.springframework.security.web.savedrequest.SavedRequest savedRequest =
                    (org.springframework.security.web.savedrequest.SavedRequest) session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
            if (savedRequest != null) {
                session.removeAttribute("SPRING_SECURITY_SAVED_REQUEST"); // 소비 후 제거
                return savedRequest.getRedirectUrl();
            }
        }
        return defaultTargetUrl; // 생성자에서 받은 기본 URL
    }
}
