package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import lombok.extern.slf4j.Slf4j; // 로깅 추가

@Slf4j // 로깅 추가
public class OttStateHandler implements MfaStateHandler {

    @Override
    public boolean supports(MfaState state) {
        // 이 핸들러는 OTT Factor가 처리 중일 때의 FACTOR_CHALLENGE_INITIATED 또는 FACTOR_VERIFICATION_PENDING 상태를 담당.
        return state == MfaState.FACTOR_CHALLENGE_INITIATED || state == MfaState.FACTOR_VERIFICATION_PENDING;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        log.debug("[MFA StateHandler] OttStateHandler: Current state: {}, Event: {}, User: {}, Session ID: {}",
                ctx.getCurrentState(), event, ctx.getUsername(), ctx.getMfaSessionId());

        // 이 핸들러가 호출될 때는 FactorContext.getCurrentProcessingFactor()가 AuthType.OTT 여야 함.
        if (ctx.getCurrentProcessingFactor() != AuthType.OTT) {
            log.error("OttStateHandler called for a non-OTT factor. Current factor: {}, Current State: {}. Session ID: {}",
                    ctx.getCurrentProcessingFactor(), ctx.getCurrentState(), ctx.getMfaSessionId());
            throw new IllegalStateException("OttStateHandler called for a non-OTT factor. Current factor: " + ctx.getCurrentProcessingFactor() + ", Current State: " + ctx.getCurrentState());
        }

        MfaState currentState = ctx.getCurrentState();

        if (currentState == MfaState.FACTOR_CHALLENGE_INITIATED) {
            if (event == MfaEvent.SUBMIT_CREDENTIAL) { // 사용자가 OTT 코드를 제출
                log.info("OTT credential submitted for user {}. Session ID: {}", ctx.getUsername(), ctx.getMfaSessionId());
                ctx.updateLastActivityTimestamp(); // FactorContext에 마지막 활동 시간 업데이트 메소드 필요
                return MfaState.FACTOR_VERIFICATION_PENDING; // 검증 대기 상태로 변경
            } else if (event == MfaEvent.ERROR || event == MfaEvent.CHALLENGE_DELIVERY_FAILURE) { // OTT 챌린지 생성/발송 중 오류 발생 시
                log.warn("Error or challenge delivery failure during OTT initiation for user {}. Event: {}. Session ID: {}",
                        ctx.getUsername(), event, ctx.getMfaSessionId());
                return MfaState.AWAITING_FACTOR_SELECTION; // 다시 선택 화면으로 (또는 MFA_FAILURE_TERMINAL)
            }
        } else if (currentState == MfaState.FACTOR_VERIFICATION_PENDING) {
            // 실제 OTT 코드 검증 성공/실패에 따른 상태 전이는
            // MfaContinuationHandler 또는 MfaFailureHandler가 처리.
            // 이 StateHandler는 직접 MfaState.MFA_VERIFICATION_COMPLETED 등으로 전이시키지 않음.
            // TIMEOUT과 같은 특정 이벤트만 처리 가능.
            if (event == MfaEvent.TIMEOUT) {
                log.warn("OTT verification timed out for user {}. Session ID: {}", ctx.getUsername(), ctx.getMfaSessionId());
                return MfaState.MFA_SESSION_INVALIDATED; // 세션 무효화
            }
            // VERIFICATION_SUCCESS, VERIFICATION_FAILURE 이벤트는 VerificationPendingStateHandler에서 처리
        }

        log.warn("OttStateHandler: Unsupported event {} in state {}. User: {}, Session ID: {}",
                event, currentState, ctx.getUsername(), ctx.getMfaSessionId());
        throw new InvalidTransitionException(currentState, event);
    }
}