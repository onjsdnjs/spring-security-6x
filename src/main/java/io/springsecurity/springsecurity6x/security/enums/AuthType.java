package io.springsecurity.springsecurity6x.security.enums;

import io.springsecurity.springsecurity6x.security.core.asep.annotation.SecurityCookieValue;

public enum AuthType {
    FORM,
    REST,
    PASSKEY,
    OTT,
    MFA,
    MFA_FORM,
    MFA_REST,
    RECOVERY_CODE,
    PRIMARY
}
