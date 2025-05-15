package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class MfaStepBasedSuccessHandler implements AuthenticationSuccessHandler {

    private final TokenService tokenService; // Bean 주입
    private final MfaPolicyProvider mfaPolicyProvider; // Bean 주입
    private final ContextPersistence contextPersistence; // Bean 주입

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        FactorContext factorContext = contextPersistence.contextLoad(request);

        if (factorContext == null) {
            log.warn("MFA Success Handler: FactorContext is null. This should not happen at this stage. Redirecting to login.");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "MFA session expired or invalid.");
            return;
        }

        AuthType currentFactorJustCompleted = factorContext.getCurrentProcessingFactor();
        if (currentFactorJustCompleted == null) {
            log.error("MFA Success Handler: Current processing factor is null in FactorContext. Session: {}", factorContext.getMfaSessionId());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA context error.");
            contextPersistence.deleteContext(request);
            return;
        }

        log.info("MFA Step Success: Factor {} for user {} (session {}) completed by Spring Security filter.",
                currentFactorJustCompleted, factorContext.getUsername(), factorContext.getMfaSessionId());

        factorContext.recordAttempt(currentFactorJustCompleted, true, currentFactorJustCompleted + " verified successfully by filter.");
        mfaPolicyProvider.evaluateMfaPolicy(factorContext); // 정책 재평가 (완료된 Factor 반영 등)

        AuthType nextFactorToProcess = mfaPolicyProvider.determineNextFactor(factorContext);

        Map<String, Object> jsonResponse = new HashMap<>();

        if (nextFactorToProcess != null) {
            log.info("MFA Step Success: Next factor to process for user {} is {}. Session: {}",
                    factorContext.getUsername(), nextFactorToProcess, factorContext.getMfaSessionId());

            factorContext.setCurrentProcessingFactor(nextFactorToProcess); // 다음 처리할 Factor 설정
            // 다음 상태는 보통 챌린지 시작 또는 Factor 선택이 될 수 있음
            // StateMachineManager를 직접 호출하기보다, MfaPolicyProvider가 상태 결정에 관여하거나,
            // 여기서는 다음 UI 페이지로 안내하는 역할에 집중
            // factorContext.changeState(MfaState.AWAITING_MFA_FACTOR_SELECTION); // 예시 상태 변경
            contextPersistence.saveContext(factorContext, request);

            jsonResponse.put("status", "MFA_CONTINUE");
            jsonResponse.put("message", currentFactorJustCompleted + " 인증 성공. 다음 인증(" + nextFactorToProcess + ")을 진행하세요.");
            jsonResponse.put("mfaSessionId", factorContext.getMfaSessionId()); // 세션 ID 재확인

            // 클라이언트가 다음 UI 페이지로 이동할 수 있도록 URL 제공
            // 이 URL은 LoginController에서 해당 Factor의 GET 페이지를 반환해야 함
            if (nextFactorToProcess == AuthType.OTT) {
                jsonResponse.put("nextStepUrl", "/mfa/verify/ott");
            } else if (nextFactorToProcess == AuthType.PASSKEY) {
                jsonResponse.put("nextStepUrl", "/mfa/verify/passkey");
            } else {
                // 다른 Factor 유형 또는 Factor 선택 페이지로
                jsonResponse.put("nextStepUrl", "/mfa/select-factor");
            }
            response.setStatus(HttpServletResponse.SC_OK);

        } else {
            // 모든 MFA 단계 완료
            log.info("MFA Step Success: All MFA factors completed for user {}. Issuing final tokens. Session: {}",
                    factorContext.getUsername(), factorContext.getMfaSessionId());
            // factorContext.changeState(MfaState.MFA_FULLY_COMPLETED); // 최종 완료 상태 (선택적)

            String deviceId = (String) factorContext.getAttribute("deviceId"); // 1차 인증 시 저장된 deviceId
            if (deviceId == null) deviceId = request.getHeader("X-Device-Id"); // Fallback

            Authentication finalAuthentication = factorContext.getPrimaryAuthentication();

            String accessToken = tokenService.createAccessToken(finalAuthentication, deviceId);
            String refreshTokenVal = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshTokenVal = tokenService.createRefreshToken(finalAuthentication, deviceId);
            }

            jsonResponse.put("status", "MFA_COMPLETE");
            jsonResponse.put("message", "MFA 인증이 성공적으로 완료되었습니다.");
            jsonResponse.put("accessToken", accessToken);
            if (refreshTokenVal != null) {
                jsonResponse.put("refreshToken", refreshTokenVal);
            }
            jsonResponse.put("redirectUrl", "/"); // 성공 시 리다이렉트할 기본 URL

            contextPersistence.deleteContext(request); // 성공 후 MFA 컨텍스트 삭제
            response.setStatus(HttpServletResponse.SC_OK);
        }

        response.setContentType("application/json;charset=UTF-8");
        tokenService.getObjectMapper().writeValue(response.getWriter(), jsonResponse);
    }
}