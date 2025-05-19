package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import lombok.RequiredArgsConstructor; // 추가
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.CollectionUtils;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider; // 추가

@Slf4j
@RequiredArgsConstructor // MfaPolicyProvider 주입을 위해
public class FactorSelectionStateHandler implements MfaStateHandler {

    private final MfaPolicyProvider mfaPolicyProvider; // 추가

    @Override
    public boolean supports(MfaState state) {
        return state == MfaState.AWAITING_FACTOR_SELECTION;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        log.debug("[MFA StateHandler] FactorSelection: Current state: {}, Event: {}, User: {}, Session ID: {}",
                ctx.getCurrentState(), event, ctx.getUsername(), ctx.getMfaSessionId());

        // 이 상태에서는 사용자가 Factor를 선택했다는 FACTOR_SELECTED 이벤트를 기대.
        // 이 이벤트는 MfaApiController의 /api/mfa/select-factor 엔드포인트에서 처리 후 발생시킬 수 있음.
        if (event == MfaEvent.FACTOR_SELECTED) {
            AuthType selectedFactor = ctx.getCurrentProcessingFactor(); // MfaApiController에서 설정한 값
            if (selectedFactor == null) {
                log.error("FACTOR_SELECTED event received, but no currentProcessingFactor set in FactorContext. User: {}, Session ID: {}",
                        ctx.getUsername(), ctx.getMfaSessionId());
                // 시스템 오류 또는 재선택 유도
                return MfaState.MFA_SYSTEM_ERROR; // 또는 AWAITING_MFA_FACTOR_SELECTION
            }

            // 선택된 Factor가 사용 가능한지 다시 한번 확인 (MfaPolicyProvider 사용)
            if (!mfaPolicyProvider.isFactorAvailableForUser(ctx.getUsername(), selectedFactor, ctx)) {
                log.warn("User '{}' selected factor {} which is not available as per policy. Returning to selection. Session ID: {}",
                        ctx.getUsername(), selectedFactor, ctx.getMfaSessionId());
                ctx.recordAttempt(selectedFactor, false, "Attempted to use an unavailable factor: " + selectedFactor);
                ctx.setCurrentProcessingFactor(null); // 잘못된 선택이므로 현재 처리 Factor 초기화
                return MfaState.AWAITING_FACTOR_SELECTION;
            }

            log.info("User '{}' selected factor: {}. Proceeding to initiate challenge. Session ID: {}",
                    ctx.getUsername(), selectedFactor, ctx.getMfaSessionId());
            return MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION;
        }

        // 기존 SUBMIT_CREDENTIAL 이벤트 처리는 FACTOR_SELECTED 이벤트로 대체.
        // FactorContext.currentProcessingFactor는 API 컨트롤러에서 설정됨.

        log.warn("FactorSelectionStateHandler: Unsupported event {} in state {}. User: {}, Session ID: {}",
                event, ctx.getCurrentState(), ctx.getUsername(), ctx.getMfaSessionId());
        throw new InvalidTransitionException(ctx.getCurrentState(), event);
    }
}

