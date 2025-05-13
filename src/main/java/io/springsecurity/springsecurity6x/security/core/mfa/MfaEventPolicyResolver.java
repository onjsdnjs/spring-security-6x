package io.springsecurity.springsecurity6x.security.core.mfa;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import jakarta.servlet.http.HttpServletRequest;

import static io.springsecurity.springsecurity6x.security.enums.MfaEvent.*;

public class MfaEventPolicyResolver {

    /**
     * MFA 이벤트를 결정하는 정책 로직
     * - 1순위: 클라이언트가 명시한 event 파라미터
     * - 2순위: 요청 경로 기반 heuristic fallback
     * - 3순위: 현재 상태 기반 전이 후보 추론
     */
    public static MfaEvent resolve(HttpServletRequest req, FactorContext ctx) {
        // 1. 명시적 event 파라미터
        String ev = req.getParameter("event");
        if (ev != null) {
            try {
                return MfaEvent.valueOf(ev.toUpperCase());
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("지원하지 않는 MFA 이벤트: " + ev);
            }
        }

        // 2. URI 기반 추론
        String path = req.getRequestURI().toLowerCase();
        boolean isChallengeRequest = path.contains("/challenge") || path.contains("/options") || path.endsWith("/step");
        if (isChallengeRequest) return REQUEST_CHALLENGE;

        // 3. 상태 기반 추론
        return switch (ctx.currentState()) {
            case INIT -> REQUEST_CHALLENGE;
            case FORM_CHALLENGE, REST_CHALLENGE, OTT_CHALLENGE, PASSKEY_CHALLENGE -> SUBMIT_CREDENTIAL;
            case FORM_SUBMITTED, REST_SUBMITTED, OTT_SUBMITTED, PASSKEY_SUBMITTED, TOKEN_ISSUANCE -> ISSUE_TOKEN;
            case COMPLETED -> REQUEST_CHALLENGE;
            default -> ERROR;
        };
    }
}

