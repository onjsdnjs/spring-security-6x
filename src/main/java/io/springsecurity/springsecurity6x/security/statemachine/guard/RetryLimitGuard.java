package io.springsecurity.springsecurity6x.security.statemachine.guard;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class RetryLimitGuard extends AbstractMfaStateGuard {

    private final AuthContextProperties authContextProperties;
    private static final int DEFAULT_MAX_RETRIES = 3;

    @Override
    protected boolean doEvaluate(StateContext<MfaState, MfaEvent> context, FactorContext factorContext) {
        int currentRetryCount = factorContext.getRetryCount();
        int maxRetries = getMaxRetries();

        boolean withinLimit = currentRetryCount < maxRetries;

        if (!withinLimit) {
            log.warn("Retry limit exceeded for session: {}. Current: {}, Max: {}",
                    factorContext.getMfaSessionId(), currentRetryCount, maxRetries);
        }

        return withinLimit;
    }

    private int getMaxRetries() {
        // AuthContextProperties 에서 설정값 가져오기
        // 설정이 없으면 기본값 사용
        return DEFAULT_MAX_RETRIES;
    }

    @Override
    public String getGuardName() {
        return "RetryLimitGuard";
    }

    @Override
    public String getFailureReason() {
        return "Maximum retry attempts exceeded";
    }
}