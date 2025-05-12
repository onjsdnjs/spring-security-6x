package io.springsecurity.springsecurity6x.security.enums;

/**
 * 인증 스텝 유형을 객체지향적으로 표현하는 enum
 */
public enum StepType {
    FORM {
        @Override public MfaState challengeState() { return MfaState.FORM_CHALLENGE; }
        @Override public MfaState submittedState() { return MfaState.FORM_SUBMITTED; }
    },
    REST {
        @Override public MfaState challengeState() { return MfaState.REST_CHALLENGE; }
        @Override public MfaState submittedState() { return MfaState.REST_SUBMITTED; }
    },
    OTT {
        @Override public MfaState challengeState() { return MfaState.OTT_CHALLENGE; }
        @Override public MfaState submittedState() { return MfaState.OTT_SUBMITTED; }
    },
    PASSKEY {
        @Override public MfaState challengeState() { return MfaState.PASSKEY_CHALLENGE; }
        @Override public MfaState submittedState() { return MfaState.PASSKEY_SUBMITTED; }
    };

    /** 챌린지 상태 */
    public abstract MfaState challengeState();
    /** 제출 상태 */
    public abstract MfaState submittedState();

    public static StepType of(String type) {
        try {
            return StepType.valueOf(type.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown step type: " + type, e);
        }
    }
}
