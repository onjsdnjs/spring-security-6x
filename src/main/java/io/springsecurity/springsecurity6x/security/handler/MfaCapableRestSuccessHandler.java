package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportResult; // 추가
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie; // 추가
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class MfaCapableRestSuccessHandler implements AuthenticationSuccessHandler {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final TokenService tokenService;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter; // 주입

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        log.info("MFA Capable REST Success Handler for user: {}", authentication.getName());
        String deviceId = getEffectiveDeviceId(request);
        FactorContext mfaCtx = new FactorContext(authentication);
        mfaCtx.setAttribute("deviceId", deviceId);
        mfaPolicyProvider.evaluateMfaPolicy(mfaCtx);

        if (mfaCtx.isMfaRequired()) {
            log.info("MFA is required for user: {}. Guiding to MFA selection.", authentication.getName());
            contextPersistence.saveContext(mfaCtx, request);
            Map<String, Object> mfaRequiredDetails = new HashMap<>();
            mfaRequiredDetails.put("status", "MFA_REQUIRED");
            mfaRequiredDetails.put("message", "1차 인증 성공. 2차 인증이 필요합니다.");
            mfaRequiredDetails.put("mfaSessionId", mfaCtx.getMfaSessionId());
            mfaRequiredDetails.put("nextStepUrl", authContextProperties.getMfa().getInitiateUrl());
            responseWriter.writeSuccessResponse(response, mfaRequiredDetails, HttpServletResponse.SC_OK);
        } else {
            log.info("MFA not required for user: {}. Issuing tokens.", authentication.getName());
            String accessToken = tokenService.createAccessToken(authentication, deviceId);
            String refreshTokenVal = tokenService.properties().isEnableRefreshToken() ?
                    tokenService.createRefreshToken(authentication, deviceId) : null;

            TokenTransportResult transportResult = tokenService.prepareTokensForTransport(accessToken, refreshTokenVal);

            if (transportResult.getCookiesToSet() != null) {
                for (ResponseCookie cookie : transportResult.getCookiesToSet()) {
                    response.addHeader("Set-Cookie", cookie.toString());
                }
            }
            responseWriter.writeSuccessResponse(response, transportResult.getBody(), HttpServletResponse.SC_OK);
            contextPersistence.deleteContext(request); // 사용 완료된 컨텍스트 삭제
        }
    }
    private String getEffectiveDeviceId(HttpServletRequest request) { /* ... 이전과 동일 ... */
        String deviceId = request.getHeader("X-Device-Id");
        FactorContext factorContext = contextPersistence.contextLoad(request);

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
        if (deviceId == null) deviceId = UUID.randomUUID().toString();
        log.debug("Effective Device ID for {}: {}", request.getRemoteUser() , deviceId);
        return deviceId;
    }
}
