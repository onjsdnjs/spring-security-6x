package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;     // 추가
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;     // 새로운 MfaState 사용
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException; // 가정된 경로

public class OttStateHandler implements MfaStateHandler {

    @Override
    public boolean supports(MfaState state) {
        // 이 핸들러는 OTT Factor가 처리 중일 때의 FACTOR_CHALLENGE_INITIATED 또는 FACTOR_VERIFICATION_PENDING 상태를 담당.
        // StateHandlerRegistry 에서 이 핸들러를 선택할 때, FactorContext의 currentProcessingFactor가 OTT 인지도 함께 고려되어야 이상적임.
        return state == MfaState.FACTOR_CHALLENGE_INITIATED || state == MfaState.FACTOR_VERIFICATION_PENDING;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        // 이 핸들러가 호출될 때는 FactorContext.getCurrentProcessingFactor()가 AuthType.OTT 여야 함.
        if (ctx.getCurrentProcessingFactor() != AuthType.OTT) {
            // 이 핸들러는 OTT Factor가 아닐 경우 호출되어서는 안 됨.
            // 예외를 발생시켜 잘못된 핸들러 호출임을 알림.
            throw new IllegalStateException("OttStateHandler called for a non-OTT factor. Current factor: " + ctx.getCurrentProcessingFactor() + ", Current State: " + ctx.getCurrentState());
        }

        MfaState currentState = ctx.getCurrentState();

        if (currentState == MfaState.FACTOR_CHALLENGE_INITIATED) {
            if (event == MfaEvent.SUBMIT_CREDENTIAL) { // 사용자가 OTT 코드를 제출
                ctx.getLastActivityTimestamp();
                return MfaState.FACTOR_VERIFICATION_PENDING; // 검증 대기 상태로 변경
            } else if (event == MfaEvent.ERROR) { // OTT 챌린지 생성/발송 중 일반 오류 발생 시
                // (MfaEvent에 CHALLENGE_DELIVERY_FAILURE 같은 더 구체적인 이벤트가 있다면 그것을 사용)
                // 실패 처리는 MfaFailureHandler가 담당하고, 여기서는 상태 전이만 제안.
                return MfaState.AWAITING_MFA_FACTOR_SELECTION; // 다시 선택 화면으로 (또는 MFA_FAILURE_TERMINAL)
            }
        } else if (currentState == MfaState.FACTOR_VERIFICATION_PENDING) {
            // 실제 OTT 코드 검증 성공/실패에 따른 상태 전이는
            // MfaContinuationHandler 또는 MfaFailureHandler가 처리합니다.
            // 이 StateHandler가 직접 MfaState.MFA_VERIFICATION_COMPLETED 등으로 전이시키지 않습니다.
            // 따라서 이 블록에서는 특별한 상태 전이를 정의하지 않거나,
            // 매우 제한적인 (예: TIMEOUT) 이벤트만 처리할 수 있습니다.
            if (event == MfaEvent.TIMEOUT) {
                return MfaState.MFA_SESSION_INVALIDATED; // 예시: 타임아웃 시 세션 무효화
            }
        }

        throw new InvalidTransitionException(currentState, event);
    }
}