package io.springsecurity.springsecurity6x.security.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class HandleFailureAction extends AbstractMfaStateAction {

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context, FactorContext factorContext) {
        MfaEvent event = context.getEvent();
        log.warn("Handling failure for event: {} in session: {}", event, factorContext.getMfaSessionId());

        // 재시도 카운트 증가
        int currentRetryCount = factorContext.getRetryCount();
        factorContext.setRetryCount(currentRetryCount + 1);

        // 에러 메시지 설정
        String errorMessage = determineErrorMessage(event);
        factorContext.setLastError(errorMessage);

        // 실패 이유 로깅
        log.info("MFA failure recorded. Retry count: {}, Error: {}",
                factorContext.getRetryCount(), errorMessage);
    }

    private String determineErrorMessage(MfaEvent event) {
        switch (event) {
            case FACTOR_VERIFICATION_FAILED:
            case OTT_VERIFICATION_FAILED:
                return "Invalid verification code";
            case PASSKEY_VERIFICATION_FAILED:
                return "Passkey verification failed";
            case CHALLENGE_ISSUANCE_FAILED:
                return "Failed to issue challenge";
            case RETRY_LIMIT_EXCEEDED:
                return "Maximum retry attempts exceeded";
            default:
                return "Authentication failed";
        }
    }

    @Override
    public String getActionName() {
        return "HandleFailureAction";
    }
}