package io.springsecurity.springsecurity6x.security.utils;

import io.springsecurity.springsecurity6x.security.enums.MfaState;

public class AuthUtil {

    public static boolean isTerminalState(MfaState state) {
        return state == MfaState.TOKEN_ISSUANCE || state == MfaState.COMPLETED;
    }
}
