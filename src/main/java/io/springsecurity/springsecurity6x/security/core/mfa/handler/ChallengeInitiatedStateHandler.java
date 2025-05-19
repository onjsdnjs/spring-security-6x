package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ChallengeInitiatedStateHandler implements MfaStateHandler {

    @Override
    public boolean supports(MfaState state) {
        return state == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION; // 이름 변경에 따른 수정
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        log.debug("[MFA StateHandler] ChallengeInitiated: Current state: {}, Event: {}, Factor: {}, Session ID: {}",
                ctx.getCurrentState(), event, ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());

        // 이 상태에서는 주로 MfaContinuationFilter가 UI를 안내하고,
        // 사용자가 UI에서 상호작용 후 Factor 검증 URL로 요청을 보내면
        // MfaStepFilterWrapper와 해당 Factor의 스프링 시큐리티 필터가 처리.
        // 따라서 이 핸들러는 특별한 이벤트를 처리할 필요가 없을 수 있음.
        // 만약 MfaContinuationFilter에서 이 핸들러를 호출하여 다음 상태를 결정한다면,
        // 예를 들어 "챌린지 UI가 성공적으로 로드되었다"는 가정 하에 상태를 변경할 수 있음.

        if (event == MfaEvent.CHALLENGE_DELIVERED) { // (가상의 이벤트, 실제로는 UI 로드 성공 후 상태 변경)
            log.info("Challenge UI for factor {} presumed delivered. Transitioning to await verification. Session: {}",
                    ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());
            return MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION;
        } else if (event == MfaEvent.ERROR || event == MfaEvent.CHALLENGE_DELIVERY_FAILURE) {
            log.warn("Error or delivery failure during challenge initiation for factor {}. Session: {}",
                    ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());
            return MfaState.AWAITING_FACTOR_SELECTION; // 오류 시 다시 선택 화면으로
        }

        log.warn("ChallengeInitiatedStateHandler: Unsupported event {} in state {}. Session ID: {}",
                event, ctx.getCurrentState(), ctx.getMfaSessionId());
        throw new InvalidTransitionException(ctx.getCurrentState(), event);
    }
}
