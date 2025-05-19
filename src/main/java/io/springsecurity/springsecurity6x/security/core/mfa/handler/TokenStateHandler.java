package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;

@Slf4j // 추가
@RequiredArgsConstructor // 추가
public class TokenStateHandler implements MfaStateHandler {

    @Override
    public boolean supports(MfaState state) {
        // 이전 VerificationPendingStateHandler에서 모든 Factor 완료 시 ALL_FACTORS_COMPLETED 상태로 전이.
        // 이 상태에서 ISSUE_TOKEN 이벤트가 발생하면 최종 완료로.
        return state == MfaState.ALL_FACTORS_COMPLETED;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        log.debug("[MFA StateHandler] TokenState: Current state: {}, Event: {}, User: {}, Session ID: {}",
                ctx.getCurrentState(), event, ctx.getUsername(), ctx.getMfaSessionId());

        if (ctx.getCurrentState() == MfaState.ALL_FACTORS_COMPLETED) {
            if (event == MfaEvent.ISSUE_TOKEN) { // 최종 토큰 발급 요청 이벤트
                log.info("All MFA factors verified for user '{}'. Proceeding to final completion (token issuance). Session ID: {}",
                        ctx.getUsername(), ctx.getMfaSessionId());
                // 실제 토큰 발급은 이 상태 변경 후 호출될 최종 성공 핸들러 (예: JwtEmittingAndMfaAwareSuccessHandler)가 담당.
                // 사용자 제공 MfaState.java에 MFA_FULLY_COMPLETED가 없으면 ALL_FACTORS_COMPLETED가 최종 성공 상태일 수 있음.
                // 여기서는 사용자 제공 MfaState.java에 MFA_FULLY_COMPLETED가 없다고 가정하고,
                // ALL_FACTORS_COMPLETED를 이미 최종 성공 직전 상태로 간주.
                // 만약 MfaState.java에 MFA_FULLY_COMPLETED가 있다면 그 상태로 전이.
                // return MfaState.MFA_FULLY_COMPLETED;

                // 이 핸들러는 상태 전이만 제안. 실제 토큰 발급은 아님.
                // ALL_FACTORS_COMPLETED 상태 자체가 "토큰 발급 대기"를 의미한다고 볼 수 있음.
                // 또는, MfaState에 TOKEN_ISSUANCE_PENDING 같은 상태를 추가하고 그 상태로 전이 후,
                // ISSUE_TOKEN 이벤트로 MFA_FULLY_COMPLETED로 갈 수 있음.
                // 현재 MfaState.java 기준으로, ALL_FACTORS_COMPLETED에서 ISSUE_TOKEN 이벤트 발생 시,
                // 추가적인 상태 변경 없이 이 상태를 유지하고, 실제 토큰 발급은 외부 핸들러가 수행.
                // 여기서는 "MFA_FULLY_COMPLETED" 상태가 enum에 있다고 가정하고 해당 상태로 전이. (없다면 ALL_FACTORS_COMPLETED 유지 또는 에러)
                if (Arrays.stream(MfaState.values()).anyMatch(s -> s.name().equals("MFA_FULLY_COMPLETED"))) {
                    return MfaState.valueOf("MFA_FULLY_COMPLETED");
                } else {
                    log.warn("MfaState.MFA_FULLY_COMPLETED is not defined. Treating ALL_FACTORS_COMPLETED as final success state before token issuance. Session ID: {}", ctx.getMfaSessionId());
                    // 이 경우, 더 이상 상태 변경 없이 ALL_FACTORS_COMPLETED를 유지하고,
                    // 외부 핸들러가 이 상태를 보고 토큰을 발급.
                    // 또는, 에러를 발생시켜 MfaState enum 정의가 필요함을 알릴 수 있음.
                    // 여기서는 유효한 다음 상태가 없으므로 예외 발생 또는 현재 상태 유지.
                    // 더 안전하게는, MfaState.ALL_FACTORS_COMPLETED에서 ISSUE_TOKEN은 더 이상 상태 전이를 일으키지 않고,
                    // 이 상태 자체가 "토큰 발급 가능"을 의미하도록 설계.
                    // 여기서는 InvalidTransitionException을 던져서 이 이벤트가 더 이상 상태를 바꾸지 않음을 명시.
                    throw new InvalidTransitionException(ctx.getCurrentState(), event);
                }
            }
        }
        log.warn("TokenStateHandler: Unsupported event {} in state {}. User: {}, Session ID: {}",
                event, ctx.getCurrentState(), ctx.getUsername(), ctx.getMfaSessionId());
        throw new InvalidTransitionException(ctx.getCurrentState(), event);
    }
}

