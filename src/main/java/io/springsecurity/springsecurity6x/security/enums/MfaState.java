package io.springsecurity.springsecurity6x.security.enums;

public enum MfaState {
    INIT,
    FORM_CHALLENGE,
    FORM_SUBMITTED,
    OTT_CHALLENGE,
    OTT_SUBMITTED,
    PASSKEY_CHALLENGE,
    PASSKEY_SUBMITTED,
    TOKEN_ISSUANCE,
    COMPLETED,
    RECOVERY
}
