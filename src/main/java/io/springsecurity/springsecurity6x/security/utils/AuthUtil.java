package io.springsecurity.springsecurity6x.security.utils;

import io.springsecurity.springsecurity6x.security.enums.MfaState;

/**
 * MfaState가 최종 완료 또는 실패 상태인지 확인합니다.
 * @param state 확인할 MfaState
 * @return 터미널 상태이면 true
 */
public static boolean isTerminalState(MfaState state) {
    if (state == null) {
        return false;
    }
    return state.isTerminal(); // MfaState enum 자체의 isTerminal() 메소드 활용
}
