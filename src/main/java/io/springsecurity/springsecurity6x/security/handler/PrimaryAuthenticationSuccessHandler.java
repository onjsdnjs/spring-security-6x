package io.springsecurity.springsecurity6x.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
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
public class PrimaryAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final TokenService tokenService;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;
    private final ObjectMapper objectMapper; // JSON 응답 생성용

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        log.info("Primary authentication successful for user: {}. Evaluating MFA policy.", authentication.getName());

        // 이전 MFA 컨텍스트가 있다면 삭제 (새로운 1차 인증 시작이므로)
        contextPersistence.deleteContext(request);

        FactorContext mfaCtx = new FactorContext(authentication);
        String deviceId = getEffectiveDeviceId(request, mfaCtx);
        mfaCtx.setAttribute("deviceId", deviceId); // 나중에 토큰 발급 등에 사용될 수 있도록 저장

        // MfaPolicyProvider가 FactorContext의 mfaRequired, registeredFactors,
        // currentProcessingFactor, currentMfaState 등을 설정
        mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(authentication, mfaCtx);

        if (mfaCtx.isMfaRequiredAsPerPolicy()) {
            log.info("MFA is required for user: {}. Guiding to MFA initiation. Session ID: {}",
                    authentication.getName(), mfaCtx.getMfaSessionId());
            contextPersistence.saveContext(mfaCtx, request); // MFA 세션 시작, 컨텍스트 저장

            Map<String, Object> mfaRequiredDetails = new HashMap<>();
            mfaRequiredDetails.put("status", "MFA_REQUIRED");
            mfaRequiredDetails.put("message", "Primary authentication successful. MFA is required.");
            mfaRequiredDetails.put("mfaSessionId", mfaCtx.getMfaSessionId());
            mfaRequiredDetails.put("username", authentication.getName()); // 클라이언트에서 사용
            // MfaContinuationFilter가 처리할 다음 URL (application.yml에서 설정)
            mfaRequiredDetails.put("nextStepUrl", request.getContextPath() + authContextProperties.getMfa().getInitiateUrl());

            responseWriter.writeSuccessResponse(response, mfaRequiredDetails, HttpServletResponse.SC_OK);
        } else {
            log.info("MFA is not required for user: {}. Issuing final tokens.", authentication.getName());
            // MFA 불필요: 최종 인증 성공 처리 (예: JWT 발급)
            String accessToken = tokenService.createAccessToken(authentication, deviceId);
            String refreshTokenVal = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshTokenVal = tokenService.createRefreshToken(authentication, deviceId);
            }

            TokenTransportResult transportResult = tokenService.prepareTokensForTransport(accessToken, refreshTokenVal);

            if (transportResult.getCookiesToSet() != null) {
                for (ResponseCookie cookie : transportResult.getCookiesToSet()) {
                    response.addHeader("Set-Cookie", cookie.toString());
                }
            }
            Map<String, Object> responseBody = new HashMap<>(transportResult.getBody());
            responseBody.put("status", "SUCCESS"); // MFA_REQUIRED 대신 일반 성공 상태
            responseBody.put("message", "Authentication successful.");
            responseBody.put("redirectUrl", "/"); // 예시: 홈으로 리다이렉트
            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
        }
    }

    private String getEffectiveDeviceId(HttpServletRequest request, FactorContext factorContext) {
        String deviceId = request.getHeader("X-Device-Id");
        if (factorContext != null && StringUtils.hasText((String) factorContext.getAttribute("deviceId"))) {
            deviceId = (String) factorContext.getAttribute("deviceId");
            if (StringUtils.hasText(deviceId)) log.debug("Using deviceId from FactorContext: {}", deviceId);
        }
        if (!StringUtils.hasText(deviceId)) {
            HttpSession session = request.getSession(false); // 새 세션 만들지 않음
            if (session != null) {
                deviceId = (String) session.getAttribute("sessionDeviceIdForAuth");
                if (StringUtils.hasText(deviceId)) log.debug("Using deviceId from HTTP session attribute: {}", deviceId);
            }
        }
        if (!StringUtils.hasText(deviceId)) {
            // 최후의 수단: 새 UUID 생성 (이 경우, 같은 브라우저라도 요청마다 다른 ID가 될 수 있으므로 주의)
            // 실제 운영에서는 클라이언트가 일관된 Device ID를 보내도록 유도하는 것이 좋음.
            deviceId = UUID.randomUUID().toString();
            log.debug("No existing deviceId found, generated new transient deviceId: {}", deviceId);
        }
        return deviceId;
    }
}