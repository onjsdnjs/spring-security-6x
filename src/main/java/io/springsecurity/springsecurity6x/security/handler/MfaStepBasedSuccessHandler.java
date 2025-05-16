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
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class MfaStepBasedSuccessHandler implements AuthenticationSuccessHandler, OneTimeTokenGenerationSuccessHandler { // 인터페이스 추가

    private final TokenService tokenService;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final ContextPersistence contextPersistence;

    /**
     * 일반적인 AuthenticationSuccessHandler 구현 (예: Form, REST, Passkey 스텝 후)
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        log.debug("MfaStepBasedSuccessHandler.onAuthenticationSuccess called for user: {}", authentication.getName());
        processMfaStepSuccess(request, response, authentication);
    }

    /**
     * OneTimeTokenGenerationSuccessHandler 구현 (OTT 스텝 후)
     * OneTimeTokenAuthenticationFilter는 인증 성공 시 이 메서드를 호출하고 OneTimeToken 객체를 전달합니다.
     * 이 메서드에서는 전달받은 OneTimeToken에서 사용자 정보를 얻어 Authentication 객체를 만들거나,
     * SecurityContextHolder에서 이미 설정된 Authentication 객체를 사용할 수 있습니다.
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken token)
            throws IOException, ServletException {
        // OneTimeTokenAuthenticationFilter가 SecurityContext에 Authentication을 설정했을 것으로 가정.
        // 만약 설정하지 않았다면, token.getUsername() 등을 사용하여 Authentication 객체를 여기서 만들어야 함.
        Authentication authentication = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            // 이 경우는 OneTimeTokenAuthenticationFilter의 설정 오류 또는 예상치 못한 흐름일 수 있음.
            // token에서 username을 가져와 로깅하고 에러 처리.
            String usernameFromToken = (token != null && token.getUsername() != null) ? token.getUsername() : "Unknown OTT User";
            log.warn("MfaStepBasedSuccessHandler.handle (OTT): Authentication not found in SecurityContext after OTT consumption for user derived from token: {}. This might indicate an issue with OneTimeTokenAuthenticationFilter setup.", usernameFromToken);
            // 적절한 오류 응답 또는 리다이렉션
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication context not established after OTT step.");
            return;
        }
        log.debug("MfaStepBasedSuccessHandler.handle (OTT) called for user: {} with token for: {}", authentication.getName(), token.getUsername());
        processMfaStepSuccess(request, response, authentication);
    }


    private void processMfaStepSuccess(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Authentication authentication) throws IOException, ServletException {

        FactorContext factorContext = contextPersistence.contextLoad(request);

        if (factorContext == null) {
            log.warn("MFA Step Success Handler: FactorContext is null. Cannot determine next MFA step or issue tokens. User: {}", authentication.getName());
            // 이 경우, MFA 흐름이 비정상적으로 중단되었거나, 세션이 유실되었을 수 있음.
            // 오류 페이지로 리다이렉트하거나 오류 응답 전송.
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "MFA session context is missing.");
            return;
        }

        AuthType currentFactorJustCompleted = factorContext.getCurrentProcessingFactor();
        if (currentFactorJustCompleted == null) {
            log.error("MFA Step Success Handler: Current processing factor is null in FactorContext. Session: {}, User: {}", factorContext.getMfaSessionId(), authentication.getName());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA context error: current factor unknown.");
            contextPersistence.deleteContext(request);
            return;
        }

        log.info("MFA Step Success: Factor {} for user {} (session {}) completed.",
                currentFactorJustCompleted, factorContext.getUsername(), factorContext.getMfaSessionId());

        // 이미 필터 레벨에서 성공했으므로 여기서는 recordAttempt를 할 필요는 없을 수 있음. (또는 중복 호출 방지)
        // factorContext.recordAttempt(currentFactorJustCompleted, true, currentFactorJustCompleted + " verified successfully.");
        mfaPolicyProvider.evaluateMfaPolicy(factorContext); // 정책 재평가 (완료된 Factor 반영 등)

        AuthType nextFactorToProcess = mfaPolicyProvider.determineNextFactor(factorContext);
        Map<String, Object> jsonResponse = new HashMap<>();

        if (nextFactorToProcess != null) {
            log.info("MFA Step Success: Next factor to process for user {} is {}. Session: {}",
                    factorContext.getUsername(), nextFactorToProcess, factorContext.getMfaSessionId());

            factorContext.setCurrentProcessingFactor(nextFactorToProcess);
            contextPersistence.saveContext(factorContext, request);

            jsonResponse.put("status", "MFA_CONTINUE");
            jsonResponse.put("message", currentFactorJustCompleted + " 인증 성공. 다음 인증(" + nextFactorToProcess + ")을 진행하세요.");
            jsonResponse.put("mfaSessionId", factorContext.getMfaSessionId());
            jsonResponse.put("nextFactorType", nextFactorToProcess.name()); // 클라이언트가 다음 factor 타입을 알 수 있도록 추가

            // 클라이언트가 다음 UI 페이지로 이동할 수 있도록 URL 제공
            if (nextFactorToProcess == AuthType.OTT) {
                jsonResponse.put("nextStepUrl", "/mfa/verify/ott");
            } else if (nextFactorToProcess == AuthType.PASSKEY) {
                jsonResponse.put("nextStepUrl", "/mfa/verify/passkey");
            } else if (nextFactorToProcess == AuthType.RECOVERY_CODE){ // 복구 코드 예시
                jsonResponse.put("nextStepUrl", "/mfa/verify/recovery");
            } else {
                log.warn("Unknown next MFA factor type: {}. Redirecting to factor selection.", nextFactorToProcess);
                jsonResponse.put("nextStepUrl", "/mfa/select-factor"); // 기본적으로 선택 페이지로
            }
            response.setStatus(HttpServletResponse.SC_OK);

        } else {
            // 모든 MFA 단계 완료
            log.info("MFA Step Success: All MFA factors completed for user {}. Issuing final tokens. Session: {}",
                    factorContext.getUsername(), factorContext.getMfaSessionId());

            String deviceId = (String) factorContext.getAttribute("deviceId");
            if (deviceId == null) deviceId = request.getHeader("X-Device-Id"); // Fallback
            if (deviceId == null) { // 그래도 없으면 새로 생성 (최후의 수단)
                deviceId = java.util.UUID.randomUUID().toString();
                log.warn("Device ID not found in FactorContext or request header for user {}. Generated a new one: {}", factorContext.getUsername(), deviceId);
            }


            Authentication finalAuthentication = factorContext.getPrimaryAuthentication() != null ? factorContext.getPrimaryAuthentication() : authentication;

            String accessToken = tokenService.createAccessToken(finalAuthentication, deviceId);
            String refreshTokenVal = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshTokenVal = tokenService.createRefreshToken(finalAuthentication, deviceId);
            }

            jsonResponse.put("status", "MFA_COMPLETE"); // 또는 "SUCCESS"
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