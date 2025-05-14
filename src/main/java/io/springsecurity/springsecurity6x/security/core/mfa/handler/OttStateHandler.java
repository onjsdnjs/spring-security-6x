package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;

public class OttStateHandler implements MfaStateHandler {

    @Override
    public boolean supports(MfaState state) {
        // 이 핸들러는 OTT Factor가 처리 중일 때의 특정 상태들을 담당합니다.
        // StateHandlerRegistry가 상태만으로 핸들러를 선택한다면, 이 핸들러가 호출되었을 때
        // FactorContext를 통해 현재 처리 대상이 OTT인지 추가 확인이 필요할 수 있습니다.
        // 더 나은 방법은 MfaState 자체에 Factor 정보를 포함하거나 (예: OTT_CHALLENGE_REQUESTED),
        // Registry가 Factor 정보도 함께 고려하여 핸들러를 선택하는 것입니다.
        // 현재는 MfaState.FACTOR_CHALLENGE_INITIATED 와 FACTOR_VERIFICATION_PENDING 상태를 지원한다고 가정.
        return state == MfaState.FACTOR_CHALLENGE_INITIATED || state == MfaState.FACTOR_VERIFICATION_PENDING;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        // 이 핸들러가 호출되었다면, 외부에서 이미 현재 Factor가 OTT라고 판단했거나,
        // 또는 이 핸들러 내부에서 FactorType을 확인해야 합니다.
        if (ctx.getCurrentProcessingFactor() != AuthType.OTT) {
            // 이 핸들러는 OTT Factor를 위한 것이므로, 다른 Factor가 처리 중이면 관여하지 않음.
            // 또는 예외를 발생시켜 잘못된 핸들러 호출임을 알릴 수 있음.
            // 여기서는 예외를 발생시키지 않고, 상태 변화 없이 현재 상태를 반환하거나,
            // supports에서 걸러졌다고 가정합니다.
            // 더 안전하게는 supports(MfaState state, FactorContext ctx)로 변경하거나,
            // 여기서 명시적으로 확인하고 예외를 던지는 것이 좋습니다.
            // throw new IllegalStateException("OttStateHandler called for non-OTT factor: " + ctx.getCurrentProcessingFactor());
        }

        MfaState currentState = ctx.getCurrentState();

        if (currentState == MfaState.FACTOR_CHALLENGE_INITIATED && ctx.getCurrentProcessingFactor() == AuthType.OTT) {
            // (예: OTT 코드/링크 발송 요청 이벤트 -> 발송 성공 후 상태 변경은 외부에서 처리)
            // 사용자가 OTT 코드를 제출하는 이벤트 (SUBMIT_CREDENTIAL)
            if (event == MfaEvent.SUBMIT_CREDENTIAL) {
                // 실제 코드 검증 로직은 이 핸들러의 책임이 아님.
                // 코드 제출 시, 검증을 기다리는 상태로 변경.
                // 실제 검증은 MfaFactorAuthenticator (가칭) 또는 관련 Spring Security 필터에서 수행.
                ctx.getLastActivityTimestamp();
                return MfaState.FACTOR_VERIFICATION_PENDING;
            }
        }
        // FACTOR_VERIFICATION_PENDING 상태에서의 이벤트 처리는
        // 주로 MfaContinuationHandler 또는 MfaFailureHandler를 통해 이루어집니다.
        // 이 상태 핸들러가 직접 최종 성공/실패 상태로 전이시키는 것은 바람직하지 않을 수 있습니다.

        // 지원하지 않는 이벤트/상태 조합
        throw new InvalidTransitionException(currentState, event);
    }
}
