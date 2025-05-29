package io.springsecurity.springsecurity6x.security.statemachine.guard;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class FactorAvailabilityGuard extends AbstractMfaStateGuard {

    @Override
    protected boolean doEvaluate(StateContext<MfaState, MfaEvent> context, FactorContext factorContext) {
        // selectedFactor를 메시지 헤더나 변수에서 가져와야 함
        String selectedFactor = (String) context.getMessageHeader("selectedFactor");
        if (selectedFactor == null) {
            selectedFactor = (String) context.getExtendedState().getVariables().get("selectedFactor");
        }

        if (selectedFactor == null) {
            log.error("No selected factor found in context for session: {}",
                    factorContext.getMfaSessionId());
            return false;
        }

        try {
            AuthType requestedFactor = AuthType.valueOf(selectedFactor.toUpperCase());

            // 사용자가 등록한 팩터 목록에서 확인
            boolean isAvailable = factorContext.getRegisteredMfaFactors() != null &&
                    factorContext.getRegisteredMfaFactors().contains(requestedFactor);

            if (!isAvailable) {
                log.warn("Factor {} is not available for user {} in session {}",
                        requestedFactor, factorContext.getUsername(), factorContext.getMfaSessionId());
            }

            return isAvailable;

        } catch (IllegalArgumentException e) {
            log.error("Invalid factor type: {} for session: {}",
                    selectedFactor, factorContext.getMfaSessionId());
            return false;
        }
    }

    @Override
    public String getGuardName() {
        return "FactorAvailabilityGuard";
    }

    @Override
    public String getFailureReason() {
        return "Selected authentication factor is not available";
    }
}