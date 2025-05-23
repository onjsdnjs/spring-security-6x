package io.springsecurity.springsecurity6x.security.statemachine.guard;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

/**
 * 재시도 제한을 확인하는 Guard
 * 팩터별 또는 전체 재시도 횟수를 관리
 */
@Slf4j
@Component
public class RetryLimitGuard extends AbstractMfaStateGuard {

    private final AuthContextProperties authContextProperties;

    public RetryLimitGuard(AuthContextProperties authContextProperties) {
        this.authContextProperties = authContextProperties;
    }

    @Override
    protected boolean doEvaluate(StateContext<MfaState, MfaEvent> context,
                                 FactorContext factorContext) {
        String sessionId = factorContext.getMfaSessionId();
        int currentRetryCount = factorContext.getRetryCount();
        int maxRetries = getMaxRetries();

        // 현재 팩터별 재시도 횟수 확인
        String currentFactor = factorContext.getCurrentProcessingFactor() != null ?
                factorContext.getCurrentProcessingFactor().name() : null;
        if (currentFactor != null) {
            Integer factorRetryCount = getFactorRetryCount(factorContext, currentFactor);
            int factorMaxRetries = getFactorMaxRetries(currentFactor);

            log.debug("Session {}: Factor {} retry count={}/{}",
                    sessionId, currentFactor, factorRetryCount, factorMaxRetries);

            if (factorRetryCount >= factorMaxRetries) {
                log.warn("Factor {} retry limit exceeded for session: {}",
                        currentFactor, sessionId);
                return false;
            }
        }

        // 전체 재시도 횟수 확인
        boolean withinLimit = currentRetryCount < maxRetries;

        log.debug("Session {}: Total retry count={}/{}, within limit={}",
                sessionId, currentRetryCount, maxRetries, withinLimit);

        if (!withinLimit) {
            log.warn("Total retry limit exceeded for session: {}", sessionId);
        }

        return withinLimit;
    }

    /**
     * 최대 재시도 횟수 가져오기
     */
    private int getMaxRetries() {
        // 기본값 3
        return 3;
    }

    /**
     * 팩터별 최대 재시도 횟수 가져오기
     */
    private int getFactorMaxRetries(String factorType) {
        // 팩터 타입별 기본값
        switch (factorType.toUpperCase()) {
            case "OTT":
            case "SMS":
                return 5; // OTT/SMS는 더 많은 재시도 허용
            case "TOTP":
            case "FIDO":
            case "PASSKEY":
                return 3; // 기본값
            default:
                return getMaxRetries(); // 전체 설정값 사용
        }
    }

    /**
     * 특정 팩터의 재시도 횟수 가져오기
     */
    private Integer getFactorRetryCount(FactorContext factorContext, String factorType) {
        String key = "retryCount_" + factorType;
        Object retryCount = factorContext.getAttribute(key);

        if (retryCount instanceof Integer) {
            return (Integer) retryCount;
        }

        return 0;
    }

    /**
     * 재시도 횟수 증가
     */
    public void incrementRetryCount(FactorContext factorContext) {
        // 전체 재시도 횟수 증가
        factorContext.setRetryCount(factorContext.getRetryCount() + 1);

        // 팩터별 재시도 횟수 증가
        String currentFactor = factorContext.getCurrentProcessingFactor() != null ?
                factorContext.getCurrentProcessingFactor().name() : null;
        if (currentFactor != null) {
            String key = "retryCount_" + currentFactor;
            Integer currentCount = getFactorRetryCount(factorContext, currentFactor);
            factorContext.setAttribute(key, currentCount + 1);
        }

        log.info("Retry count incremented for session: {}, total: {}",
                factorContext.getMfaSessionId(), factorContext.getRetryCount());
    }

    /**
     * 재시도 횟수 초기화
     */
    public void resetRetryCount(FactorContext factorContext, String factorType) {
        if (factorType != null) {
            String key = "retryCount_" + factorType;
            factorContext.removeAttribute(key);
            log.debug("Reset retry count for factor {} in session: {}",
                    factorType, factorContext.getMfaSessionId());
        }
    }

    @Override
    public String getFailureReason() {
        return "Maximum retry attempts exceeded";
    }

    /**
     * 남은 재시도 횟수 계산
     */
    public int getRemainingRetries(FactorContext factorContext) {
        int maxRetries = getMaxRetries();
        int currentRetries = factorContext.getRetryCount();
        return Math.max(0, maxRetries - currentRetries);
    }

    /**
     * 특정 팩터의 남은 재시도 횟수 계산
     */
    public int getFactorRemainingRetries(FactorContext factorContext, String factorType) {
        int maxRetries = getFactorMaxRetries(factorType);
        int currentRetries = getFactorRetryCount(factorContext, factorType);
        return Math.max(0, maxRetries - currentRetries);
    }

    @Override
    public String getGuardName() {
        return "RetryLimitGuard";
    }
}