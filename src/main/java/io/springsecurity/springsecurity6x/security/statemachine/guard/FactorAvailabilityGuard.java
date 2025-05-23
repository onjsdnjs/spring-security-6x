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
        MfaEvent event = context.getEvent();
        AuthType requestedFactor = null;

        // 이벤트에서 요청된 Factor 추출
        switch (event) {
            case FACTOR_SELECTED_OTT:
                requestedFactor = AuthType.OTT;
                break;
            case FACTOR_SELECTED_PASSKEY:
                requestedFactor = AuthType.PASSKEY;
                break;
            default:
                // Factor 선택 이벤트가 아닌 경우
                return true;
        }

        // 사용 가능한 Factor 목록에서 확인
        boolean isAvailable = factorContext.getAvailableFactors() != null &&
                factorContext.getAvailableFactors().contains(requestedFactor);

        if (!isAvailable) {
            log.warn("Factor {} is not available for user {} in session {}",
                    requestedFactor, factorContext.getUsername(), factorContext.getMfaSessionId());
        }

        return isAvailable;
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