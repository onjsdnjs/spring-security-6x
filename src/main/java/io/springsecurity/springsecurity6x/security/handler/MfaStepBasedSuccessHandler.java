package io.springsecurity.springsecurity6x.security.handler;

// ... (imports)
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportResult;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.ott.OneTimeToken; // OTT 핸들링 위해 추가
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler; // OTT 핸들링 위해 추가
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Slf4j
@Component // 스프링 빈으로 등록
@RequiredArgsConstructor
public class MfaStepBasedSuccessHandler implements AuthenticationSuccessHandler, OneTimeTokenGenerationSuccessHandler { // OneTimeTokenGenerationSuccessHandler 추가 (단일 OTT 성공 후에도 사용될 수 있으므로)

    private final TokenService tokenService;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final ContextPersistence contextPersistence;
    private final AuthResponseWriter responseWriter;
    // finalSuccessHandler는 AuthenticationFlowConfig에서 가져오거나,
    // 이 핸들러 자체가 최종 성공 처리까지 담당할 수 있음. 여기서는 직접 처리.

    // 일반적인 MFA Factor 성공 시 호출 (예: Passkey 검증 성공 후)
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        log.debug("MfaStepBasedSuccessHandler.onAuthenticationSuccess called for user: {} (Principal type: {})",
                authentication.getName(), authentication.getPrincipal().getClass().getSimpleName());
        processMfaStepSuccess(request, response, authentication);
    }

    // OTT Factor 성공 시 호출 (OneTimeTokenAuthenticationFilter가 이 핸들러를 직접 호출하도록 설정)
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken token)
            throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || !Objects.equals(authentication.getName(), token.getUsername())) {
            log.warn("MfaStepBasedSuccessHandler.handle (OTT): Authentication mismatch or not found in SecurityContext after OTT. OTT User: {}. Auth User: {}",
                    token.getUsername(), (authentication != null ? authentication.getName() : "N/A"));
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "OTT_AUTH_CONTEXT_ERROR", "OTT 인증 후 사용자 컨텍스트 오류.", request.getRequestURI());
            return;
        }
        log.debug("MfaStepBasedSuccessHandler.handle (OTT) called for authenticated user: {} via OTT for: {}",
                authentication.getName(), token.getUsername());
        processMfaStepSuccess(request, response, authentication);
    }

    private void processMfaStepSuccess(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Authentication authentication) throws IOException {

        FactorContext factorContext = contextPersistence.contextLoad(request);
        if (factorContext == null || !Objects.equals(factorContext.getUsername(), authentication.getName())) {
            log.warn("MFA Step Success Handler: FactorContext is null or username mismatch. User: {}, Context User: {}. Session may have expired or been corrupted.",
                    authentication.getName(), (factorContext != null ? factorContext.getUsername() : "N/A"));
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "MFA_SESSION_INVALID_OR_MISMATCH", "MFA 세션이 유효하지 않거나 사용자 정보가 일치하지 않습니다.", request.getRequestURI());
            return;
        }

        AuthType currentFactorJustCompleted = factorContext.getCurrentProcessingFactor();
        if (currentFactorJustCompleted == null) {
            log.error("MFA Step Success Handler: Critical error - currentProcessingFactor is null in FactorContext. Session: {}, User: {}", factorContext.getMfaSessionId(), factorContext.getUsername());
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA_CONTEXT_CORRUPTED_FACTOR", "MFA 컨텍스트에 현재 처리 중인 인증 요소 정보가 없습니다.", request.getRequestURI());
            contextPersistence.deleteContext(request);
            return;
        }

        log.info("MFA Step Success: Factor {} for user {} (session {}) completed successfully.",
                currentFactorJustCompleted, factorContext.getUsername(), factorContext.getMfaSessionId());

        factorContext.addCompletedFactor(currentFactorJustCompleted);
        AuthType nextFactorToProcess = mfaPolicyProvider.determineNextFactorToProcess(factorContext);
        Map<String, Object> responseBody = new HashMap<>();

        if (nextFactorToProcess != null) {
            log.info("MFA Step Success: Next factor to process for user {} is {}. Session: {}",
                    factorContext.getUsername(), nextFactorToProcess, factorContext.getMfaSessionId());
            factorContext.setCurrentProcessingFactor(nextFactorToProcess);
            factorContext.changeState(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION); // 다음 Factor 챌린지 시작 대기
            contextPersistence.saveContext(factorContext, request);

            responseBody.put("status", "MFA_CONTINUE");
            responseBody.put("message", currentFactorJustCompleted.name() + " 인증 성공. 다음 " + nextFactorToProcess.name() + " 인증을 진행하세요.");
            responseBody.put("mfaSessionId", factorContext.getMfaSessionId());
            responseBody.put("nextFactorType", nextFactorToProcess.name().toUpperCase()); // 일관성을 위해 대문자
            // 클라이언트가 이 URL로 GET 요청하여 해당 Factor의 챌린지 UI를 받도록 함
            responseBody.put("nextStepUrl", request.getContextPath() + "/mfa/challenge/" + nextFactorToProcess.name().toLowerCase());
            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
        } else {
            // 모든 MFA 단계 완료
            log.info("MFA Step Success: All MFA factors completed for user {}. Issuing final tokens. Session: {}",
                    factorContext.getUsername(), factorContext.getMfaSessionId());
            factorContext.changeState(MfaState.ALL_FACTORS_COMPLETED); // 최종 완료 직전 상태

            // AuthenticationFlowConfig에 finalSuccessHandler가 설정되어 있다면 그것을 사용.
            // 여기서는 JwtEmittingAndMfaAwareSuccessHandler가 최종 처리를 한다고 가정하고,
            // 해당 핸들러가 호출되도록 SecurityConfig에서 설정하거나, 여기서 직접 토큰 발급.
            // 더 일반적인 접근은 finalSuccessHandler를 주입받아 호출하는 것.
            // 여기서는 이 핸들러가 최종 토큰 발급까지 담당하는 것으로 간주 (기존 코드의 JwtEmittingAndMfaAwareSuccessHandler와 유사 역할 수행)

            String deviceId = (String) factorContext.getAttribute("deviceId");
            Authentication finalAuthentication = factorContext.getPrimaryAuthentication(); // 1차 인증 객체 사용

            String accessToken = tokenService.createAccessToken(finalAuthentication, deviceId);
            String refreshTokenVal = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshTokenVal = tokenService.createRefreshToken(finalAuthentication, deviceId);
            }

            contextPersistence.deleteContext(request); // MFA 컨텍스트 정리

            TokenTransportResult transportResult = tokenService.prepareTokensForTransport(accessToken, refreshTokenVal);

            if (transportResult.getCookiesToSet() != null) {
                for (ResponseCookie cookie : transportResult.getCookiesToSet()) {
                    response.addHeader("Set-Cookie", cookie.toString());
                }
            }
            // body에는 이미 accessToken 등이 포함되어 있음. 추가 정보만 설정.
            Map<String, Object> finalSuccessBody = new HashMap<>(transportResult.getBody());
            finalSuccessBody.put("status", "MFA_COMPLETE"); // 또는 "SUCCESS"
            finalSuccessBody.put("message", "모든 MFA 인증이 성공적으로 완료되었습니다.");
            finalSuccessBody.put("redirectUrl", "/"); // 최종 성공 시 이동할 URL (클라이언트에서 사용)
            responseWriter.writeSuccessResponse(response, finalSuccessBody, HttpServletResponse.SC_OK);
        }
    }
}