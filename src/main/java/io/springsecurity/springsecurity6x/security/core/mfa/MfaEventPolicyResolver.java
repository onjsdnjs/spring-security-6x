package io.springsecurity.springsecurity6x.security.core.mfa;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;

public class MfaEventPolicyResolver {

    public static MfaEvent resolve(HttpServletRequest req, FactorContext ctx) {
        String ev = req.getParameter("event");
        if (ev != null) {
            try {
                return MfaEvent.valueOf(ev.toUpperCase());
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("Unsupported MFA event: " + ev);
            }
        }

        String path = req.getRequestURI().toLowerCase();
        // URI 기반 추론은 현재 MFA 단계/상황에 따라 더 정교하게 정의 필요
        // 예: if (path.endsWith("/options") || path.endsWith("/challenge")) return MfaEvent.REQUEST_CHALLENGE;
        //     if (path.endsWith("/verify") || path.endsWith("/submit")) return MfaEvent.SUBMIT_CREDENTIAL;

        // 상태 기반 추론 (새로운 MfaState 기준으로 전면 재검토 필요)
        MfaState currentState = ctx.getCurrentState();
        if (currentState == null) return MfaEvent.ERROR;

        return switch (currentState) {
            case PRIMARY_AUTHENTICATION_COMPLETED -> {
                // MFA 필요 여부, 자동 시도 Factor 등에 따라 다음 이벤트 결정
                // 예: if (ctx.getPreferredAutoAttemptFactor() != null) yield MfaEvent.REQUEST_CHALLENGE; (자동 시도)
                //     else yield MfaEvent.REQUEST_CHALLENGE; // 또는 Factor 선택 페이지로 안내하는 이벤트
                yield MfaEvent.REQUEST_CHALLENGE; // 단순화된 예시
            }
            case AWAITING_MFA_FACTOR_SELECTION -> {
                // 사용자가 Factor를 선택하는 요청이라면 해당 Factor에 대한 챌린지 요청 이벤트
                // 예: String selectedFactor = req.getParameter("selectedFactor");
                //     if (selectedFactor != null) return MfaEvent.REQUEST_CHALLENGE; // (selectedFactor 정보와 함께)
                yield MfaEvent.SUBMIT_CREDENTIAL; // 단순화된 예시 (선택 후 바로 제출로 가정)
            }
            case FACTOR_CHALLENGE_INITIATED -> MfaEvent.SUBMIT_CREDENTIAL; // 챌린지 화면에서 사용자가 응답 제출
            case FACTOR_VERIFICATION_PENDING -> {
                // 검증 결과에 따라 다름. 여기서는 이벤트 해석이므로, 이 상태는 보통 다음 필터에서 처리됨.
                // 만약 이 필터에서 최종 토큰 발급 이벤트를 결정해야 한다면,
                // MfaPolicyProvider 등을 통해 모든 Factor가 완료되었는지 확인 후 ISSUE_TOKEN 반환
                // if (allFactorsCompleted(ctx)) yield MfaEvent.ISSUE_TOKEN;
                yield MfaEvent.ERROR; // 일반적으로 이 상태에서 직접 이벤트 해석은 어려움
            }
            case MFA_VERIFICATION_COMPLETED -> MfaEvent.ISSUE_TOKEN; // 모든 Factor 검증 완료 후 토큰 발급 요청
            // ... 기타 상태에 대한 처리 ...
            default -> MfaEvent.ERROR; // 정의되지 않은 상태 또는 부적절한 시점
        };
    }
}

