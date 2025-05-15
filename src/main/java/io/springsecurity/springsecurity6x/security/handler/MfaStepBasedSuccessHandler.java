package io.springsecurity.springsecurity6x.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Slf4j
@RequiredArgsConstructor
public class MfaStepBasedSuccessHandler implements AuthenticationSuccessHandler {

    private final TokenService tokenService;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final ContextPersistence contextPersistence;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        FactorContext factorContext = contextPersistence.contextLoad(request);

        if (factorContext == null) {
            log.warn("MFA Success Handler: FactorContext is null. Cannot proceed with MFA flow. Redirecting to login.");
            response.sendRedirect("/loginForm?error=mfa_session_expired");
            return;
        }

        AuthType currentFactorJustCompleted = factorContext.getCurrentProcessingFactor();
        log.info("MFA Step Success: Factor {} for user {} (session {}) completed.",
                currentFactorJustCompleted, factorContext.getUsername(), factorContext.getMfaSessionId());

        factorContext.recordAttempt(currentFactorJustCompleted, true, currentFactorJustCompleted + " verified successfully.");

        // MfaPolicyProvider를 사용하여 다음 진행할 Factor 또는 최종 완료 여부 결정
        // 이 부분은 MfaPolicyProvider.evaluateMfaPolicy(factorContext)를 통해
        // factorContext 내부의 isMfaRequired, registeredMfaFactors, completedFactors 등을 업데이트하고,
        // 다음 currentProcessingFactor를 설정하거나, 모든 Factor 완료 시 특정 상태로 변경하도록 설계.

        // 예시: 간단히 모든 등록된 Factor가 완료되었는지 확인 (실제로는 더 정교한 로직 필요)
        // factorContext에 완료된 factor 목록을 기록하고, mfaPolicyProvider가 이를 참조하여 다음 단계를 결정한다고 가정.
        // mfaPolicyProvider.evaluateMfaPolicy(factorContext); // 정책 재평가

        AuthType nextFactorToProcess = mfaPolicyProvider.determineNextFactor(factorContext);

        if (nextFactorToProcess != null) {
            log.info("MFA Step Success: Next factor to process for user {} is {}. Guiding to factor selection or next step.",
                    factorContext.getUsername(), nextFactorToProcess);
            factorContext.setCurrentProcessingFactor(nextFactorToProcess);
            factorContext.changeState(MfaState.AWAITING_MFA_FACTOR_SELECTION); // 또는 바로 FACTOR_CHALLENGE_INITIATED
            contextPersistence.saveContext(factorContext, request);

            // 클라이언트가 다음 Factor 선택 페이지로 가도록 유도하거나,
            // 다음 Factor가 명확하면 해당 Factor의 검증 페이지로 바로 안내.
            // 여기서는 Factor 선택 페이지로 다시 안내하는 것을 기본으로 함.
            // 또는, JSON 응답으로 다음 단계 정보를 클라이언트에 전달할 수도 있음.
            // response.sendRedirect("/mfa/select-factor");

            // API 기반으로 클라이언트에게 다음 단계 안내
            Map<String, Object> mfaContinueResponse = new HashMap<>();
            mfaContinueResponse.put("status", "MFA_CONTINUE");
            mfaContinueResponse.put("message", currentFactorJustCompleted + " 인증 성공. 다음 인증을 진행하세요.");
            mfaContinueResponse.put("nextStepUrl", "/mfa/select-factor"); // 또는 특정 factor 검증 페이지
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json;charset=UTF-8");
            new ObjectMapper().writeValue(response.getWriter(), mfaContinueResponse);

        } else {
            // 모든 MFA 단계 완료
            log.info("MFA Step Success: All MFA factors completed for user {}. Issuing final tokens.", factorContext.getUsername());
            factorContext.changeState(MfaState.MFA_FULLY_COMPLETED); // 최종 완료 상태
            // contextPersistence.saveContext(factorContext, request); // 저장 후 삭제

            // 최종 토큰 발급 (TokenIssuingSuccessHandler의 로직과 유사)
            String deviceId = factorContext.getDeviceId(); // FactorContext 생성 시 저장된 deviceId 사용
            if (deviceId == null) deviceId = request.getHeader("X-Device-Id"); // Fallback

            Authentication finalAuthentication = factorContext.getPrimaryAuthentication(); // 1차 인증 객체 사용

            String accessToken = tokenService.createAccessToken(finalAuthentication, deviceId);
            String refreshToken = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshToken = tokenService.createRefreshToken(finalAuthentication, deviceId);
            }
            tokenService.writeAccessAndRefreshToken(response, accessToken, refreshToken); // 이 메소드가 응답을 커밋

            contextPersistence.deleteContext(request); // 성공 후 MFA 컨텍스트 삭제
        }
    }
}