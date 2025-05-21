package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

@Slf4j
@Component
@RequiredArgsConstructor
public class OneTimeTokenCreationSuccessHandler implements OneTimeTokenGenerationSuccessHandler {

    private final ContextPersistence contextPersistence;
    private final AuthContextProperties authContextProperties;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken token)
            throws IOException, ServletException {
        log.info("OneTimeTokenCreationSuccessHandler: Token generated for user '{}'", token.getUsername());

        FactorContext factorContext = contextPersistence.contextLoad(request);
        String usernameFromToken = token.getUsername(); // 생성된 토큰의 사용자

        // MFA 흐름인지, 단일 OTT 흐름인지 구분
        // FactorContext가 존재하고, flowTypeName이 "mfa"이며, 현재 OTT 처리 중인 경우
        if (factorContext != null &&
                AuthType.MFA.name().equalsIgnoreCase(factorContext.getFlowTypeName()) &&
                Objects.equals(factorContext.getUsername(), usernameFromToken) &&
                factorContext.getCurrentProcessingFactor() == AuthType.OTT) {

            log.debug("MFA OTT code generation successful for user: {}. Session ID: {}",
                    factorContext.getUsername(), factorContext.getMfaSessionId());

            // 상태를 코드 입력 대기로 변경 (MfaContinuationFilter에서도 처리 가능하지만, 여기서도 명시적으로 설정 가능)
            // 이 핸들러는 GenerateOneTimeTokenFilter 직후에 호출되므로, 아직 코드 입력 화면으로 가기 전.
            // 이 상태 변경은 /mfa/challenge/ott 로 GET 요청 시 MfaContinuationFilter가 수행하는 것이 더 적절할 수 있음.
            // 여기서는 일단 로깅만 하고, 리다이렉션에 집중.
            // factorContext.changeState(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
            // contextPersistence.saveContext(factorContext, request);

            String challengeUiUrl = authContextProperties.getMfa().getOttFactor().getChallengeUrl(); // 예: /mfa/challenge/ott
            if (!StringUtils.hasText(challengeUiUrl)) {
                challengeUiUrl = "/mfa/challenge/ott"; // 기본값
                log.warn("MFA OTT challengeUrl not configured, using default: {}", challengeUiUrl);
            }
            String redirectUrl = request.getContextPath() + challengeUiUrl;
            log.info("Redirecting to MFA OTT challenge page: {}", redirectUrl);
            response.sendRedirect(redirectUrl);
            return;
        }

        // 단일 OTT 흐름 (예: /loginOtt 페이지에서 코드 요청)
        // FactorContext가 없거나, 있더라도 MFA 흐름이 아닌 경우
        // 이 경우, FactorContext를 새로 만들거나 기존 것을 활용하여 flowTypeName을 'OTT'로 설정해야 함.
        // 하지만, GenerateOneTimeTokenFilter는 인증 객체를 만들지 않으므로, 여기서 FactorContext를 새로 만들긴 어려움.
        // 단일 OTT의 경우, 성공 시 단순 페이지 이동 또는 성공 메시지 전달이 주 목적.
        if ((factorContext == null || !AuthType.MFA.name().equalsIgnoreCase(factorContext.getFlowTypeName()))) {
            log.info("Single OTT token generated for user {}. Redirecting to 'ott/sent' page.", usernameFromToken);
            String email = URLEncoder.encode(usernameFromToken, StandardCharsets.UTF_8);
            String codeSentUrl = authContextProperties.getMfa().getOttFactor().getCodeSentUrl(); // 예: /ott/sent
            if (!StringUtils.hasText(codeSentUrl)) {
                codeSentUrl = "/ott/sent";
            }
            // 단일 OTT 흐름임을 명시하기 위해 flow 파라미터 추가
            String redirectUrl = request.getContextPath() + codeSentUrl +
                    "?email=" + email +
                    "&type=code_sent" + // "code_sent"로 고정 (이메일 코드 방식이므로)
                    "&flow=ott_single"; // "ott_single"로 단일 OTT 플로우 명시
            response.sendRedirect(redirectUrl);
            return;
        }

        // 위의 조건에 해당하지 않는 예외적인 경우
        log.warn("OneTimeTokenCreationSuccessHandler: Unhandled scenario or context mismatch. " +
                        "FactorContext flow: {}, FactorContext user: {}, Token user: {}. Redirecting to loginForm.",
                factorContext != null ? factorContext.getFlowTypeName() : "null",
                factorContext != null ? factorContext.getUsername() : "null",
                usernameFromToken);
        response.sendRedirect(request.getContextPath() + "/loginForm?message=ott_setup_issue");
    }
}