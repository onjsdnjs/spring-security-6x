package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportResult; // 추가
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie; // 추가
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils; // 추가

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class MfaStepBasedSuccessHandler implements AuthenticationSuccessHandler, OneTimeTokenGenerationSuccessHandler {

    private final TokenService tokenService;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final ContextPersistence contextPersistence;
    private final AuthResponseWriter responseWriter;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        log.debug("MfaStepBasedSuccessHandler.onAuthenticationSuccess called for user: {}", authentication.getName());
        processMfaStepSuccess(request, response, authentication);
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken token)
            throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            String usernameFromToken = (token != null && token.getUsername() != null) ? token.getUsername() : "Unknown OTT User";
            log.warn("MfaStepBasedSuccessHandler.handle (OTT): Authentication not found in SecurityContext for user from token: {}.", usernameFromToken);
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "AUTH_CONTEXT_MISSING_OTT_STEP", "Authentication context missing after OTT step.", request.getRequestURI());
            return;
        }
        log.debug("MfaStepBasedSuccessHandler.handle (OTT) called for authenticated user: {} with OTT for: {}", authentication.getName(), token.getUsername());
        processMfaStepSuccess(request, response, authentication);
    }

    private void processMfaStepSuccess(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Authentication authentication) throws IOException, ServletException {

        FactorContext factorContext = contextPersistence.contextLoad(request);
        if (factorContext == null) {
            log.warn("MFA Step Success Handler: FactorContext is null. User: {}", authentication.getName());
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "MFA_SESSION_MISSING", "MFA session context is missing.", request.getRequestURI());
            return;
        }

        AuthType currentFactorJustCompleted = factorContext.getCurrentProcessingFactor();
        String usernameForLog = factorContext.getUsername() != null ? factorContext.getUsername() : authentication.getName();

        if (currentFactorJustCompleted == null && factorContext.getPrimaryAuthentication() == null) {
            log.error("MFA Step Success Handler: Critical error - currentProcessingFactor and primaryAuthentication are both null in FactorContext. Session: {}, User: {}", factorContext.getMfaSessionId(), usernameForLog);
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA_CONTEXT_CORRUPTED_STEP", "MFA context is corrupted.", request.getRequestURI());
            contextPersistence.deleteContext(request);
            return;
        }
        if (currentFactorJustCompleted != null) {
            log.info("MFA Step Success: Factor {} for user {} (session {}) completed.", currentFactorJustCompleted, usernameForLog, factorContext.getMfaSessionId());
        }


        mfaPolicyProvider.evaluateMfaPolicy(factorContext); // 다음 Factor 또는 완료 여부 결정
        AuthType nextFactorToProcess = mfaPolicyProvider.determineNextFactor(factorContext);
        Map<String, Object> responseDetails = new HashMap<>();

        if (nextFactorToProcess != null) { // 다음 MFA 단계가 있는 경우
            log.info("MFA Step Success: Next factor to process for user {} is {}. Session: {}",
                    usernameForLog, nextFactorToProcess, factorContext.getMfaSessionId());
            factorContext.setCurrentProcessingFactor(nextFactorToProcess);
            contextPersistence.saveContext(factorContext, request);

            responseDetails.put("status", "MFA_CONTINUE");
            responseDetails.put("message", (currentFactorJustCompleted != null ? currentFactorJustCompleted.name() : "Previous step") + " 인증 성공. 다음 인증(" + nextFactorToProcess + ")을 진행하세요.");
            responseDetails.put("mfaSessionId", factorContext.getMfaSessionId());
            responseDetails.put("nextFactorType", nextFactorToProcess.name());
            if (nextFactorToProcess == AuthType.OTT) responseDetails.put("nextStepUrl", "/mfa/verify/ott");
            else if (nextFactorToProcess == AuthType.PASSKEY) responseDetails.put("nextStepUrl", "/mfa/verify/passkey");
            else if (nextFactorToProcess == AuthType.RECOVERY_CODE) responseDetails.put("nextStepUrl", "/mfa/verify/recovery");
            else responseDetails.put("nextStepUrl", "/mfa/select-factor"); // 기본
            responseWriter.writeSuccessResponse(response, responseDetails, HttpServletResponse.SC_OK);

        } else { // 모든 MFA 단계 완료 (nextFactorToProcess == null)
            log.info("MFA Step Success: All MFA factors completed for user {}. Issuing final tokens. Session: {}",
                    usernameForLog, factorContext.getMfaSessionId());

            String deviceId = getEffectiveDeviceId(request, factorContext); // FactorContext에서 deviceId 가져오기 시도

            Authentication finalAuthentication = factorContext.getPrimaryAuthentication() != null ? factorContext.getPrimaryAuthentication() : authentication;

            String accessToken = tokenService.createAccessToken(finalAuthentication, deviceId);
            String refreshTokenVal = null;
            if (tokenService.properties().isEnableRefreshToken()) {
                refreshTokenVal = tokenService.createRefreshToken(finalAuthentication, deviceId);
            }

            TokenTransportResult transportResult = tokenService.prepareTokensForTransport(accessToken, refreshTokenVal);

            if (transportResult.getCookiesToSet() != null) {
                for (ResponseCookie cookie : transportResult.getCookiesToSet()) {
                    response.addHeader("Set-Cookie", cookie.toString());
                }
            }
            responseWriter.writeSuccessResponse(response, transportResult.getBody(), HttpServletResponse.SC_OK);
            contextPersistence.deleteContext(request);
        }
    }
    private String getEffectiveDeviceId(HttpServletRequest request, FactorContext factorContext) {
        String deviceId = null;
        if (factorContext != null && StringUtils.hasText((String) factorContext.getAttribute("deviceId"))) {
            deviceId = (String) factorContext.getAttribute("deviceId");
            log.debug("Using deviceId from FactorContext: {}", deviceId);
        }
        if (!StringUtils.hasText(deviceId)) { // FactorContext에 없으면 헤더에서
            deviceId = request.getHeader("X-Device-Id");
            if (StringUtils.hasText(deviceId)) {
                log.debug("Using deviceId from request header: {}", deviceId);
            }
        }
        if (!StringUtils.hasText(deviceId)) { // 그래도 없으면 세션 또는 신규
            HttpSession session = request.getSession(true);
            deviceId = (String) session.getAttribute("sessionDeviceIdForAuth");
            if (deviceId == null) {
                deviceId = UUID.randomUUID().toString();
                session.setAttribute("sessionDeviceIdForAuth", deviceId);
                log.debug("Generated new session-based deviceId: {}", deviceId);
            } else {
                log.debug("Using deviceId from session attribute: {}", deviceId);
            }
        }
        return deviceId;
    }
}