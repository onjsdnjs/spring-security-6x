package io.springsecurity.springsecurity6x.security.mfa.statemachine.config;


import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaGuard;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.action.MfaAction;
import lombok.Builder;
import lombok.Getter;
import lombok.Singular;
import org.springframework.lang.Nullable;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 단일 MFA 상태 머신의 정의(상태, 이벤트, 전이, 가드, 액션)를 담는 불변 객체.
 * 이 객체는 예를 들어 AuthenticationFlowConfig에 따라 동적으로 생성될 수 있습니다.
 */
@Getter
@Builder
public class MfaStateMachineDefinition {

    private final MfaState initialState;
    private final Set<MfaState> states;
    private final MfaState endState; // 선택적 종료 상태

    @Singular("transition")
    private final List<Transition> transitions;

    // 상태별 진입/이탈 액션 (선택적)
    @Singular("onStateEntry")
    private final Map<MfaState, MfaAction> entryActions;
    @Singular("onStateExit")
    private final Map<MfaState, MfaAction> exitActions;


    @Getter
    @Builder
    public static class Transition {
        private final MfaState source;
        private final MfaState target;
        private final MfaEvent event;
        @Nullable
        private final MfaGuard guard; // null 가능
        @Nullable private final MfaAction action; // null 가능 (여러 액션이 필요하면 MfaAction 내부에서 조합)
    }
}
