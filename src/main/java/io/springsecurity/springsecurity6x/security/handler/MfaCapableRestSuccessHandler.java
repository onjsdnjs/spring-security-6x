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
        String deviceId = getEffectiveDeviceId(request); // 기존 getEffectiveDeviceId 호출 유지
        FactorContext mfaCtx = new FactorContext(authentication);
        mfaCtx.setAttribute("deviceId", deviceId);

        // 수정된 부분: evaluateMfaPolicy 대신 evaluateMfaRequirementAndDetermineInitialStep 사용
        mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(authentication, mfaCtx);

        if (mfaCtx.isMfaRequiredAsPerPolicy()) { // isMfaRequired() -> isMfaRequiredAsPerPolicy()로 변경 (FactorContext 필드명과 일치)
            log.info("MFA is required for user: {}. Guiding to MFA selection.", authentication.getName());
            contextPersistence.saveContext(mfaCtx, request);
            Map<String, Object> mfaRequiredDetails = new HashMap<>();
            mfaRequiredDetails.put("status", "MFA_REQUIRED");
            mfaRequiredDetails.put("message", "1차 인증 성공. 2차 인증이 필요합니다.");
            mfaRequiredDetails.put("mfaSessionId", mfaCtx.getMfaSessionId());
            // nextStepUrl은 MfaPolicyProvider가 evaluateMfaRequirementAndDetermineInitialStep 내에서
            // FactorContext의 currentProcessingFactor를 설정하면, MfaContinuationFilter나 클라이언트가
            // /mfa/challenge/{factorType} 등으로 이동하도록 유도하거나,
            // authContextProperties.getMfa().getInitiateUrl() (/mfa/select-factor 등)로 안내.
            // 여기서는 initiateUrl 사용이 더 적절해 보임.
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
            // 성공 응답에는 redirectUrl 등의 추가 정보가 필요할 수 있음 (클라이언트 기대에 따라)
            Map<String, Object> finalBody = new HashMap<>(transportResult.getBody());
            finalBody.put("status", "SUCCESS"); // 클라이언트가 성공 상태를 명확히 알 수 있도록
            finalBody.put("message", "Authentication successful.");
            finalBody.put("redirectUrl", "/"); // 예시: 홈으로 리다이렉트
            responseWriter.writeSuccessResponse(response, finalBody, HttpServletResponse.SC_OK);
            contextPersistence.deleteContext(request);
        }
    }

    // getEffectiveDeviceId 메소드는 기존 로직 유지 가능 (큰 문제 없음)
    private String getEffectiveDeviceId(HttpServletRequest request) {
        String deviceId = request.getHeader("X-Device-Id");
        // 아래 FactorContext 로드는 이 시점에서 거의 항상 null 이거나 이전 세션의 것일 수 있으므로,
        // 새로 생성된 FactorContext를 참조하지 않음.
        FactorContext factorContextFromSession = contextPersistence.contextLoad(request);

        if (factorContextFromSession != null && StringUtils.hasText((String) factorContextFromSession.getAttribute("deviceId"))) {
            // 이 경우는 이전 MFA 세션의 deviceId를 사용하는 것인데, 1차 인증 성공 시에는 새 deviceId를 쓰거나
            // 요청 헤더의 것을 우선하는 것이 더 일반적일 수 있음. 현재 로직은 세션 것을 우선.
            deviceId = (String) factorContextFromSession.getAttribute("deviceId");
            log.debug("Using deviceId from existing session FactorContext: {}", deviceId);
        } else if (!StringUtils.hasText(deviceId)) { // 요청 헤더에 deviceId가 없을 경우
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

        if (deviceId == null) { // 모든 경우에 deviceId가 할당되도록 최종 fallback
            deviceId = UUID.randomUUID().toString();
            log.warn("No deviceId found from header or session, generated a new transient one: {}", deviceId);
        }
        // 사용자 이름을 로그에 남길 때, 인증 전이므로 request.getRemoteUser()는 null일 수 있음.
        log.debug("Effective Device ID for current request: {}", deviceId);
        return deviceId;
    }
}
