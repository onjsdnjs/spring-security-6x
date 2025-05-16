package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter; // 추가
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
public class MfaCapableRestSuccessHandler implements AuthenticationSuccessHandler {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final TokenService tokenService;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter; // 추가: JSON 응답 생성용

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        log.info("MFA Capable REST Success Handler: Primary authentication successful for user: {}", authentication.getName());

        String deviceId = request.getHeader("X-Device-Id");
        if (!StringUtils.hasText(deviceId)) {
            deviceId = getOrCreateSessionDeviceId(request);
            log.warn("X-Device-Id header not found for user: {}. Using session-based or new deviceId: {}", authentication.getName(), deviceId);
        }

        FactorContext mfaCtx = new FactorContext(authentication);
        mfaCtx.setAttribute("deviceId", deviceId);
        mfaPolicyProvider.evaluateMfaPolicy(mfaCtx);

        if (mfaCtx.isMfaRequired()) {
            log.info("MFA is required for user: {}. Saving FactorContext and guiding to MFA selection.", authentication.getName());
            contextPersistence.saveContext(mfaCtx, request);

            Map<String, Object> mfaRequiredDetails = new HashMap<>();
            mfaRequiredDetails.put("status", "MFA_REQUIRED");
            mfaRequiredDetails.put("message", "1차 인증 성공. 2차 인증이 필요합니다.");
            mfaRequiredDetails.put("mfaSessionId", mfaCtx.getMfaSessionId());
            mfaRequiredDetails.put("nextStepUrl", authContextProperties.getMfa().getInitiateUrl());

            // MFA 안내는 토큰 발급이 아니므로 AuthResponseWriter 사용
            responseWriter.writeSuccessResponse(response, mfaRequiredDetails, HttpServletResponse.SC_OK); // SC_OK와 함께 JSON 본문 작성

        } else {
            log.info("MFA is not required for user: {}. Issuing tokens directly via TokenService.", authentication.getName());
            String accessToken = tokenService.createAccessToken(authentication, deviceId);
            String refreshTokenVal = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshTokenVal = tokenService.createRefreshToken(authentication, deviceId);
            }
            tokenService.writeAccessAndRefreshToken(response, accessToken, refreshTokenVal);
            contextPersistence.deleteContext(request); // 사용 완료된 컨텍스트 삭제
        }
    }

    private String getOrCreateSessionDeviceId(HttpServletRequest request) {
        HttpSession session = request.getSession(true);
        String deviceId = (String) session.getAttribute("sessionDeviceIdForAuth");
        if (deviceId == null) {
            deviceId = UUID.randomUUID().toString();
            session.setAttribute("sessionDeviceIdForAuth", deviceId);
            log.debug("Generated new session-based deviceId for user {}: {}", request.getRemoteUser(), deviceId);
        }
        return deviceId;
    }
}
