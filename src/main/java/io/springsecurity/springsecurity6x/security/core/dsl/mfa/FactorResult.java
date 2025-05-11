package io.springsecurity.springsecurity6x.security.core.dsl.mfa;

/**
 * 각 스텝 인증 결과
 */
public class FactorResult {
    private final boolean success;
    private final String failureReason;

    private FactorResult(boolean success, String reason) {
        this.success = success;
        this.failureReason = reason;
    }

    public static FactorResult success() {
        return new FactorResult(true, null);
    }

    public static FactorResult failure(String reason) {
        return new FactorResult(false, reason);
    }

    public boolean isSuccess() {
        return success;
    }

    public String getFailureReason() {
        return failureReason;
    }
}

