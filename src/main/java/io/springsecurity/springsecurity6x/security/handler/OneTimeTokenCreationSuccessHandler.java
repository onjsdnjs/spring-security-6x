package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.core.service.MfaStateMachineService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * 완전 일원화된 OneTimeTokenCreationSuccessHandler
 * - ContextPersistence 완전 제거
 * - MfaStateMachineService만 사용
 * - State Machine을 단일 진실의 원천으로 사용
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OneTimeTokenCreationSuccessHandler implements OneTimeTokenGenerationSuccessHandler {

    // ContextPersistence 완전 제거
    private final MfaStateMachineIntegrator mfaStateMachineIntegrator; // State Machine Service만 사용
    private final AuthContextProperties authContextProperties;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken token)
            throws IOException, ServletException {
        log.info("OneTimeTokenCreationSuccessHandler: Token generated for user '{}' via unified State Machine",
                token.getUsername());

        // 완전 일원화: State Machine에서만 FactorContext 로드
        FactorContext factorContext = loadContextFromStateMachine(request);
        String usernameFromToken = token.getUsername();

        // MFA 흐름인지, 단일 OTT 흐름인지 구분
        if (factorContext != null &&
                AuthType.MFA.name().equalsIgnoreCase(factorContext.getFlowTypeName()) &&
                Objects.equals(factorContext.getUsername(), usernameFromToken) &&
                factorContext.getCurrentProcessingFactor() == AuthType.OTT) {

            log.debug("MFA OTT code generation successful for user: {}. Session ID: {}",
                    factorContext.getUsername(), factorContext.getMfaSessionId());

            // 챌린지 발송 시간 기록
            factorContext.setAttribute("challengeInitiatedAt", System.currentTimeMillis());
            factorContext.setAttribute("ottTokenGenerated", true);
            factorContext.setAttribute("ottTokenValue", token.getTokenValue()); // 토큰 값 저장 (필요시)

            // State Machine에만 저장 (일원화)
            mfaStateMachineIntegrator.saveFactorContext(factorContext);

            String challengeUiUrl = authContextProperties.getMfa().getOttFactor().getChallengeUrl();
            if (!StringUtils.hasText(challengeUiUrl)) {
                challengeUiUrl = "/mfa/challenge/ott";
                log.warn("MFA OTT challengeUrl not configured, using default: {}", challengeUiUrl);
            }
            String redirectUrl = request.getContextPath() + challengeUiUrl;
            log.info("Redirecting to MFA OTT challenge page: {}", redirectUrl);
            response.sendRedirect(redirectUrl);
            return;
        }

        // 단일 OTT 흐름 처리
        if ((factorContext == null || !AuthType.MFA.name().equalsIgnoreCase(factorContext.getFlowTypeName()))) {
            log.info("Single OTT token generated for user {}. Redirecting to 'ott/sent' page.", usernameFromToken);
            String email = URLEncoder.encode(usernameFromToken, StandardCharsets.UTF_8);
            String codeSentUrl = authContextProperties.getMfa().getOttFactor().getCodeSentUrl();
            if (!StringUtils.hasText(codeSentUrl)) {
                codeSentUrl = "/ott/sent";
            }

            String redirectUrl = request.getContextPath() + codeSentUrl +
                    "?email=" + email +
                    "&type=code_sent" +
                    "&flow=ott_single";
            response.sendRedirect(redirectUrl);
            return;
        }

        // 예외적인 경우
        log.warn("OneTimeTokenCreationSuccessHandler: Unhandled scenario or context mismatch. " +
                        "FactorContext flow: {}, FactorContext user: {}, Token user: {}. Redirecting to loginForm.",
                factorContext != null ? factorContext.getFlowTypeName() : "null",
                factorContext != null ? factorContext.getUsername() : "null",
                usernameFromToken);
        response.sendRedirect(request.getContextPath() + "/loginForm?message=ott_setup_issue");
    }

    /**
     * 완전 일원화: State Machine에서만 FactorContext 로드
     */
    private FactorContext loadContextFromStateMachine(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            log.trace("No HttpSession found for request. Cannot load FactorContext.");
            return null;
        }

        String mfaSessionId = (String) session.getAttribute("MFA_SESSION_ID");
        if (mfaSessionId == null) {
            log.trace("No MFA session ID found in session. Cannot load FactorContext.");
            return null;
        }

        try {
            // State Machine에서 직접 로드 (일원화)
            FactorContext context = mfaStateMachineIntegrator.loadFactorContext(mfaSessionId);

            if (context != null) {
                log.debug("FactorContext loaded from unified State Machine for OTT generation: sessionId={}, state={}",
                        context.getMfaSessionId(), context.getCurrentState());
            } else {
                log.debug("No FactorContext found in unified State Machine for session: {}", mfaSessionId);
            }

            return context;
        } catch (Exception e) {
            log.error("Failed to load FactorContext from unified State Machine for session: {}", mfaSessionId, e);
            return null;
        }
    }
}