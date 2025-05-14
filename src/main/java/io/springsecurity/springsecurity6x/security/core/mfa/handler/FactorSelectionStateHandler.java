package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.CollectionUtils;

@Slf4j
public class FactorSelectionStateHandler implements MfaStateHandler {

    @Override
    public boolean supports(MfaState state) {
        return state == MfaState.AWAITING_MFA_FACTOR_SELECTION;
    }

    @Override
    public MfaState handleEvent(MfaEvent event, FactorContext ctx) {
        log.debug("[MFA Handler] FactorSelectionState: Current state: {}, Event: {}, Session ID: {}", ctx.getCurrentState(), event, ctx.getMfaSessionId());

        if (event == MfaEvent.SUBMIT_CREDENTIAL) { // 사용자가 Factor를 선택하여 제출한 경우
            AuthType selectedFactor = ctx.getCurrentProcessingFactor(); // FactorContext에 선택된 Factor가 설정되어 있어야 함
            if (selectedFactor == null) {
                log.error("[MFA Handler] FACTOR_SELECTED (via SUBMIT_CREDENTIAL) event received, but no factor set in FactorContext. Session ID: {}", ctx.getMfaSessionId());
                throw new IllegalStateException("No factor selected or set in context for FACTOR_SELECTED event.");
            }

            if (CollectionUtils.isEmpty(ctx.getRegisteredMfaFactors()) || !ctx.getRegisteredMfaFactors().contains(selectedFactor)) {
                log.warn("[MFA Handler] User '{}' selected factor {} which is not registered or no factors registered. Session ID: {}", ctx.getUsername(), selectedFactor, ctx.getMfaSessionId());
                ctx.recordAttempt(selectedFactor, false, "Attempted to use an unregistered factor: " + selectedFactor);
                // 다시 선택하도록 하거나, 오류 처리
                return MfaState.AWAITING_MFA_FACTOR_SELECTION; // 또는 MFA_FAILURE_TERMINAL
            }
            log.info("[MFA Handler] User '{}' selected factor: {}. Proceeding to challenge. Session ID: {}", ctx.getUsername(), selectedFactor, ctx.getMfaSessionId());
            return MfaState.FACTOR_CHALLENGE_INITIATED;
        }
        log.warn("[MFA Handler] FactorSelectionState: Unsupported event {} in state {}. Session ID: {}", event, ctx.getCurrentState(), ctx.getMfaSessionId());
        throw new InvalidTransitionException(ctx.getCurrentState(), event);
    }
}

