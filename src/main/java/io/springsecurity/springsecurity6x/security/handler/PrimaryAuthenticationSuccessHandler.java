package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@Slf4j
@Component // 스프링 빈으로 등록
@RequiredArgsConstructor
public class PrimaryAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider; // 주입 (이미 FactorContext 생성 시 사용되었을 수 있음)
    private final TokenService tokenService;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        log.info("PrimaryAuthenticationSuccessHandler: Primary authentication successful for user: {}. Evaluating FactorContext for MFA.", authentication.getName());

        // RestAuthenticationFilter 등에서 FactorContext가 이미 생성/저장되었을 것을 기대.
        FactorContext mfaCtx = contextPersistence.contextLoad(request);

        if (mfaCtx == null || !Objects.equals(mfaCtx.getUsername(), authentication.getName())) {
            // 1차 인증은 성공했으나, MFA 세션 컨텍스트가 없거나 사용자가 다른 경우.
            // (이론적으로는 RestAuthenticationFilter에서 이미 생성했어야 함. Form 로그인의 경우 여기서 생성 필요)
            log.warn("PrimaryAuthenticationSuccessHandler: FactorContext is null or username mismatch for user {}. Re-evaluating MFA policy.", authentication.getName());
            // 이전 FactorContext가 있다면 삭제
            contextPersistence.deleteContext(request);

            mfaCtx = new FactorContext(authentication);
            String deviceId = getEffectiveDeviceId(request, mfaCtx); // 재사용 가능한 메소드
            mfaCtx.setAttribute("deviceId", deviceId);

            // MfaPolicyProvider를 통해 MFA 필요 여부 및 초기 Factor 정보 설정
            // 이 호출은 FactorContext의 상태를 PRIMARY_AUTHENTICATION_COMPLETED에서
            // AWAITING_FACTOR_CHALLENGE_INITIATION 또는 AWAITING_FACTOR_SELECTION 등으로 변경할 수 있음.
            mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(authentication, mfaCtx);
            contextPersistence.saveContext(mfaCtx, request); // 새로 생성/평가된 컨텍스트 저장
        } else {
            // FactorContext가 이미 존재하고 유효한 경우 (예: RestAuthenticationFilter에서 생성)
            log.debug("PrimaryAuthenticationSuccessHandler: Reusing existing FactorContext (ID: {}, State: {}) for user {}",
                    mfaCtx.getMfaSessionId(), mfaCtx.getCurrentState(), authentication.getName());
            // 필요시, 이 시점에서 mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep을 다시 호출하여
            // 상태를 명시적으로 업데이트할 수도 있으나, 중복 호출을 피하기 위해 FactorContext 상태를 신뢰.
            // 단, 상태가 PRIMARY_AUTHENTICATION_COMPLETED가 아니라면, 이전 MFA 시도가 중단되었을 수 있음.
            // 이 경우, 안전하게 evaluateMfaRequirementAndDetermineInitialStep을 다시 호출하는 것이 나을 수 있음.
            if (mfaCtx.getCurrentState() == MfaState.PRIMARY_AUTHENTICATION_COMPLETED) {
                mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(authentication, mfaCtx);
                contextPersistence.saveContext(mfaCtx, request); // 변경된 상태 저장
            }
        }

        // FactorContext의 최종 평가된 상태를 기반으로 응답 결정
        if (mfaCtx.isMfaRequiredAsPerPolicy()) {
            log.info("PrimaryAuthenticationSuccessHandler: MFA is required for user: {}. Guiding to MFA initiation. Session ID: {}",
                    authentication.getName(), mfaCtx.getMfaSessionId());

            Map<String, Object> mfaRequiredDetails = new HashMap<>();
            mfaRequiredDetails.put("status", "MFA_REQUIRED");
            mfaRequiredDetails.put("message", "Primary authentication successful. MFA is required.");
            mfaRequiredDetails.put("mfaSessionId", mfaCtx.getMfaSessionId());
            mfaRequiredDetails.put("username", authentication.getName());

            // MfaContinuationFilter가 initiateUrl을 처리하므로, 해당 URL로 안내
            String initiateUrl = request.getContextPath() + authContextProperties.getMfa().getInitiateUrl();
            // 또는 MfaPolicyProvider가 결정한 첫 번째 Factor의 challenge UI로 바로 안내 가능
            // AuthType firstFactor = mfaCtx.getCurrentProcessingFactor();
            // if (firstFactor != null) {
            // initiateUrl = request.getContextPath() + "/mfa/challenge/" + firstFactor.name().toLowerCase();
            // }
            mfaRequiredDetails.put("nextStepUrl", initiateUrl);

            responseWriter.writeSuccessResponse(response, mfaRequiredDetails, HttpServletResponse.SC_OK);
        } else {
            log.info("PrimaryAuthenticationSuccessHandler: MFA is not required for user: {}. Issuing final tokens.", authentication.getName());
            // MFA 불필요: 최종 인증 성공 처리 (토큰 발급)
            String deviceId = (String) mfaCtx.getAttribute("deviceId"); // FactorContext에서 deviceId 가져오기
            if (deviceId == null) deviceId = getEffectiveDeviceId(request, mfaCtx); // 없으면 다시 가져오기

            String accessToken = tokenService.createAccessToken(authentication, deviceId);
            String refreshTokenVal = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshTokenVal = tokenService.createRefreshToken(authentication, deviceId);
            }

            contextPersistence.deleteContext(request); // MFA 플로우 안탔으므로 컨텍스트 정리

            TokenTransportResult transportResult = tokenService.prepareTokensForTransport(accessToken, refreshTokenVal);

            if (transportResult.getCookiesToSet() != null) {
                for (ResponseCookie cookie : transportResult.getCookiesToSet()) {
                    response.addHeader("Set-Cookie", cookie.toString());
                }
            }
            Map<String, Object> responseBody = new HashMap<>(transportResult.getBody());
            responseBody.put("status", "SUCCESS");
            responseBody.put("message", "Authentication successful.");
            responseBody.put("redirectUrl", "/"); // 예시: 홈으로 리다이렉트
            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
        }
    }

    // FactorContext에서 deviceId를 가져오거나 새로 생성하는 헬퍼 메소드 (중복 제거)
    private String getEffectiveDeviceId(HttpServletRequest request, @Nullable FactorContext factorContext) {
        String deviceId = null;
        if (factorContext != null) {
            deviceId = (String) factorContext.getAttribute("deviceId");
            if (StringUtils.hasText(deviceId)) {
                log.debug("Using deviceId from existing FactorContext: {}", deviceId);
                return deviceId;
            }
        }

        deviceId = request.getHeader("X-Device-Id"); // 요청 헤더에서 먼저 시도
        if (StringUtils.hasText(deviceId)) {
            log.debug("Using deviceId from request header 'X-Device-Id': {}", deviceId);
            if (factorContext != null) factorContext.setAttribute("deviceId", deviceId); // 컨텍스트에도 저장
            return deviceId;
        }

        // 헤더에 없으면 세션에서 시도 (선택적)
        HttpSession session = request.getSession(false);
        if (session != null) {
            deviceId = (String) session.getAttribute("sessionDeviceIdForAuth");
            if (StringUtils.hasText(deviceId)) {
                log.debug("Using deviceId from HTTP session attribute: {}", deviceId);
                if (factorContext != null) factorContext.setAttribute("deviceId", deviceId);
                return deviceId;
            }
        }

        // 모든 곳에 없으면 새로 생성 (UUID)
        deviceId = UUID.randomUUID().toString();
        log.debug("No existing deviceId found, generated new transient deviceId: {}", deviceId);
        if (factorContext != null) {
            factorContext.setAttribute("deviceId", deviceId);
        } else { // FactorContext가 아예 없는 경우, 세션에라도 임시 저장 (다음 요청에서 사용 가능하도록)
            HttpSession newSession = request.getSession(true);
            newSession.setAttribute("sessionDeviceIdForAuth", deviceId);
        }
        return deviceId;
    }
}