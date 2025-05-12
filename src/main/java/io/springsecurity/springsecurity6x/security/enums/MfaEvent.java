package io.springsecurity.springsecurity6x.security.enums;

public enum MfaEvent {
    REQUEST_CHALLENGE,
    SUBMIT_CREDENTIAL,
    ISSUE_TOKEN,
    RECOVER,
    TIMEOUT,
    ERROR
}
