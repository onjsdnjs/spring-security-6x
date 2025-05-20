package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
// import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class MfaCapableRestSuccessHandler implements AuthenticationSuccessHandler {

    private final ContextPersistence contextPersistence;
    // private final MfaPolicyProvider mfaPolicyProvider; // 제거: RestAuthenticationFilter에서 이미 처리
    private final TokenService tokenService;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        // RestAuthenticationFilter 에서 이미 FactorContext를 생성하고 MFA 정책 평가 및 저장을 완료했으므로,
        // 여기서는 저장된 FactorContext를 로드하여 사용합니다.
        FactorContext mfaCtx = contextPersistence.contextLoad(request);

        if (mfaCtx == null) {
            // 이 경우는 RestAuthenticationFilter에서 FactorContext 저장에 실패했거나,
            // 세션이 유실되는 등 비정상적인 상황일 수 있습니다.
            log.error("MfaCapableRestSuccessHandler: FactorContext is null after primary authentication for user: {}. This should not happen if RestAuthenticationFilter processed correctly.", authentication.getName());
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA_CONTEXT_MISSING", "MFA context is missing after primary authentication.", request.getRequestURI());
            return;
        }

        log.info("MfaCapableRestSuccessHandler: Processing for user: {}, MFA Session ID: {}, MFA Required: {}",
                authentication.getName(), mfaCtx.getMfaSessionId(), mfaCtx.isMfaRequiredAsPerPolicy());

        String deviceId = (String) mfaCtx.getAttribute("deviceId"); // FactorContext에서 deviceId 가져오기

        if (mfaCtx.isMfaRequiredAsPerPolicy()) {
            log.info("MFA is required for user: {}. Guiding to MFA selection/initiation.", authentication.getName());
            // FactorContext 에는 이미 mfaPolicyProvider에 의해 nextStepUrl 결정에 필요한 정보
            // (currentProcessingFactor, currentMfaState 등)가 설정되어 있어야 함.
            Map<String, Object> mfaRequiredDetails = new HashMap<>();
            mfaRequiredDetails.put("status", "MFA_REQUIRED");
            mfaRequiredDetails.put("message", "Primary authentication successful. MFA is required.");
            mfaRequiredDetails.put("mfaSessionId", mfaCtx.getMfaSessionId());

            // nextStepUrl 결정: FactorContext의 상태와 currentProcessingFactor를 기반으로 결정
            String nextStepUrl;
            if (mfaCtx.getCurrentProcessingFactor() != null &&
                    (mfaCtx.getCurrentState() == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION ||
                            mfaCtx.getCurrentState() == MfaState.FACTOR_CHALLENGE_INITIATED)) {
                nextStepUrl = request.getContextPath() + "/mfa/challenge/" + mfaCtx.getCurrentProcessingFactor().name().toLowerCase();
            } else {
                // 기본적으로는 Factor 선택 페이지로 유도하거나, AuthContextProperties의 initiateUrl 사용
                nextStepUrl = request.getContextPath() + authContextProperties.getMfa().getInitiateUrl();
            }
            mfaRequiredDetails.put("nextStepUrl", nextStepUrl);
            log.debug("MfaCapableRestSuccessHandler: Responding with MFA_REQUIRED, nextStepUrl: {}", nextStepUrl);
            responseWriter.writeSuccessResponse(response, mfaRequiredDetails, HttpServletResponse.SC_OK);
        } else {
            log.info("MFA not required for user: {}. Issuing final tokens.", authentication.getName());
            if (deviceId == null) { // 혹시 deviceId가 설정 안된 경우 대비
                log.warn("MfaCapableRestSuccessHandler: deviceId is null in FactorContext for user {}. Token issuance might lack device context.", authentication.getName());
                // deviceId = getOrCreateDeviceIdFallback(request); // 필요시 대체 로직
            }
            String accessToken = tokenService.createAccessToken(authentication, deviceId);
            String refreshTokenVal = tokenService.properties().isEnableRefreshToken() ?
                    tokenService.createRefreshToken(authentication, deviceId) : null;

            TokenTransportResult transportResult = tokenService.prepareTokensForTransport(accessToken, refreshTokenVal);

            if (transportResult.getCookiesToSet() != null) {
                for (ResponseCookie cookie : transportResult.getCookiesToSet()) {
                    response.addHeader("Set-Cookie", cookie.toString());
                }
            }
            Map<String, Object> finalBody = new HashMap<>(transportResult.getBody());
            finalBody.put("status", "SUCCESS");
            finalBody.put("message", "Authentication successful. MFA not required.");
            finalBody.put("redirectUrl", "/"); // 예시: 홈으로 리다이렉트
            responseWriter.writeSuccessResponse(response, finalBody, HttpServletResponse.SC_OK);
            contextPersistence.deleteContext(request); // MFA 플로우 안 탔으므로 컨텍스트 정리
        }
    }
    // getEffectiveDeviceId 메소드는 RestAuthenticationFilter로 책임이 이전되었으므로 여기서는 제거.
    // FactorContext에서 deviceId를 가져오는 것으로 충분.
}
