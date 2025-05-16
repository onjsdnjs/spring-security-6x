package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
@Component
@RequiredArgsConstructor
public class MfaCapableRestSuccessHandler implements AuthenticationSuccessHandler {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final TokenService tokenService; // 최종 토큰 발급 및 ObjectMapper 접근용
    private final AuthContextProperties authContextProperties; // MFA 다음 단계 URL 등 설정값 접근용

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException{
        log.info("MFA Capable REST Success Handler: Primary authentication successful for user: {}", authentication.getName());

        // Device ID 추출 (클라이언트 JS 에서 X-Device-Id 헤더로 전송)
        String deviceId = request.getHeader("X-Device-Id");
        if (!StringUtils.hasText(deviceId)) {
            // 헤더에 없으면 세션에서 가져오거나 새로 생성 (선택적)
            deviceId = getOrCreateSessionDeviceId(request);
            log.warn("X-Device-Id header not found. Using session-based or new deviceId: {}", deviceId);
        }

        // FactorContext 생성 (1차 인증 성공 직후)
        FactorContext mfaCtx = new FactorContext(authentication);
        mfaCtx.setAttribute("deviceId", deviceId); // FactorContext에 deviceId 저장

        // MfaPolicyProvider를 통해 이 사용자가 MFA를 사용해야 하는지,
        // 사용 가능한 Factor는 무엇인지 등을 mfaCtx에 설정
        mfaPolicyProvider.evaluateMfaPolicy(mfaCtx);

        if (mfaCtx.isMfaRequired()) {
            log.info("MFA is required for user: {}. Saving FactorContext and guiding to MFA selection.", authentication.getName());
            contextPersistence.saveContext(mfaCtx, request); // 세션 등에 FactorContext 저장

            Map<String, Object> mfaRequiredResponse = new HashMap<>();
            mfaRequiredResponse.put("status", "MFA_REQUIRED");
            mfaRequiredResponse.put("message", "1차 인증 성공. 2차 인증이 필요합니다.");
            mfaRequiredResponse.put("mfaSessionId", mfaCtx.getMfaSessionId()); // JS에서 다음 요청에 사용
            // 클라이언트가 다음으로 이동할 MFA Factor 선택 페이지 URL
            // application.yml의 spring.auth.mfa.initiate-url 사용
            mfaRequiredResponse.put("nextStepUrl", authContextProperties.getMfa().getInitiateUrl());

            response.setStatus(HttpServletResponse.SC_OK); // 1차 인증은 성공했으므로 200 OK
            response.setContentType("application/json;charset=UTF-8");
            tokenService.getObjectMapper().writeValue(response.getWriter(), mfaRequiredResponse); // ObjectMapper는 TokenService에서 가져옴

        } else {
            log.info("MFA is not required for user: {}. Issuing tokens directly.", authentication.getName());
            // MFA 불필요, 바로 토큰 발급
            String accessToken = tokenService.createAccessToken(authentication, deviceId);
            String refreshTokenVal = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshTokenVal = tokenService.createRefreshToken(authentication, deviceId);
            }

            // TokenTransportStrategy는 JSON 응답 본문에 직접 쓰지 않으므로, 여기서 JSON 직접 구성
            Map<String, Object> tokenResponse = new HashMap<>();
            tokenResponse.put("status", "SUCCESS");
            tokenResponse.put("message", "로그인 성공");
            tokenResponse.put("accessToken", accessToken);
            if (refreshTokenVal != null) {
                tokenResponse.put("refreshToken", refreshTokenVal);
            }
            tokenResponse.put("redirectUrl", "/"); // 성공 시 리다이렉트할 URL (클라이언트가 참고)

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json;charset=UTF-8");
            tokenService.getObjectMapper().writeValue(response.getWriter(), tokenResponse);

            // MFA 컨텍스트가 생성되었을 수 있으므로, 필요 없으면 삭제
            contextPersistence.deleteContext(request);
        }
    }
    private String getOrCreateSessionDeviceId(HttpServletRequest request) {
        jakarta.servlet.http.HttpSession session = request.getSession(true);
        String deviceId = (String) session.getAttribute("sessionDeviceId");
        if (deviceId == null) {
            deviceId = UUID.randomUUID().toString();
            session.setAttribute("sessionDeviceId", deviceId);
        }
        return deviceId;
    }
}
