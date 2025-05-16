package io.springsecurity.springsecurity6x.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.repository.UserRepository;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
public class JwtEmittingAndMfaAwareSuccessHandler implements AuthenticationSuccessHandler, OneTimeTokenGenerationSuccessHandler { // 인터페이스 추가

    private final TokenService tokenService;
    private final ObjectMapper objectMapper; // 생성자 주입으로 변경 (또는 tokenService 에서 가져오기)
    private final String defaultTargetUrl; // 기본 성공 URL을 필드로 가지거나, 생성자에서 받도록 수정
    private final UserRepository userRepository;
    private final ContextPersistence contextPersistence;
    private final AuthContextProperties authContextProperties;

    // AuthenticationSuccessHandler 인터페이스 메서드
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.debug("JwtEmittingAndMfaAwareSuccessHandler.onAuthenticationSuccess called for user: {}", authentication.getName());
        processAuthSuccess(request, response, authentication);
    }

    // OneTimeTokenGenerationSuccessHandler 인터페이스 메서드
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken token) throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            String usernameFromToken = (token != null && token.getUsername() != null) ? token.getUsername() : "Unknown OTT User";
            log.warn("JwtEmittingAndMfaAwareSuccessHandler.handle (OTT): Authentication not found in SecurityContext for user from token: {}", usernameFromToken);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication context not established after OTT step for JwtEmittingAndMfaAwareSuccessHandler.");
            return;
        }
        log.debug("JwtEmittingAndMfaAwareSuccessHandler.handle (OTT) called for authenticated user: {} with OTT for: {}", authentication.getName(), token.getUsername());
        processAuthSuccess(request, response, authentication);
    }

    // 공통 성공 처리 로직
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

            // MFA 정책 평가 및 초기 상태 설정 (MfaPolicyProvider가 있다면 여기서 호출)
            // 예: applicationContext.getBean(MfaPolicyProvider.class).evaluateMfaPolicy(mfaCtx);
            // 간단히는 다음 상태를 AWAITING_MFA_FACTOR_SELECTION으로 설정
            if (!mfaCtx.getRegisteredMfaFactors().isEmpty() || mfaCtx.getPreferredAutoAttemptFactor() != null ) { // 등록된 factor가 있거나 자동시도 factor가 있을때
                mfaCtx.changeState(io.springsecurity.springsecurity6x.security.enums.MfaState.AWAITING_MFA_FACTOR_SELECTION); // 초기 MFA 상태
            } else {
                // MFA 필요하지만 등록된 factor가 없는 극단적 상황. 여기서는 오류로 처리하거나, 관리자에게 알림.
                // 또는 evaluateMfaPolicy 에서 mfaRequired=false로 만들도록 유도.
                log.warn("User {} requires MFA but has no registered factors. MFA cannot proceed.", username);
                // 이 경우, MFA_REQUIRED 응답 대신 에러 응답 또는 일반 성공(토큰 발급)으로 처리해야 할 수 있음.
                // 여기서는 일단 MFA_REQUIRED로 보내되, nextStepUrl이 문제될 수 있음.
            }

            contextPersistence.saveContext(mfaCtx, request);

            Map<String, Object> mfaRequiredResponse = new HashMap<>();
            mfaRequiredResponse.put("status", "MFA_REQUIRED");
            mfaRequiredResponse.put("message", "1차 인증 성공. 2차 인증이 필요합니다.");
            mfaRequiredResponse.put("mfaSessionId", mfaCtx.getMfaSessionId());
            mfaRequiredResponse.put("nextStepUrl", authContextProperties.getMfa().getInitiateUrl()); // 예: "/mfa/select-factor"

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json;charset=UTF-8");
            objectMapper.writeValue(response.getWriter(), mfaRequiredResponse);
            return;
        }

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

    private String getEffectiveDeviceId(HttpServletRequest request, FactorContext factorContext) {
        String deviceId = request.getHeader("X-Device-Id");
        if (factorContext != null && org.springframework.util.StringUtils.hasText((String) factorContext.getAttribute("deviceId"))) {
            deviceId = (String) factorContext.getAttribute("deviceId");
        } else if (!org.springframework.util.StringUtils.hasText(deviceId)) {
            HttpSession session = request.getSession(true);
            deviceId = (String) session.getAttribute("sessionDeviceIdForAuth");
            if (deviceId == null) {
                deviceId = UUID.randomUUID().toString();
                session.setAttribute("sessionDeviceIdForAuth", deviceId);
            }
        }
        log.debug("Effective Device ID: {}", deviceId);
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
        return this.defaultTargetUrl;
    }
}