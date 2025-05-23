package io.springsecurity.springsecurity6x.security.statemachine.core;

import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.listener.StateMachineListenerAdapter;
import org.springframework.stereotype.Component;

/**
 * MFA State Machine 팩토리 구현체 (Spring State Machine 4.0.0)
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MfaStateMachineFactoryImpl implements MfaStateMachineFactory {

    private final StateMachineFactory<MfaState, MfaEvent> stateMachineFactory;

    @Override
    public StateMachine<MfaState, MfaEvent> createStateMachine(String machineId) {
        log.debug("Creating new State Machine with ID: {}", machineId);

        // Spring State Machine 4.0.0에서는 getStateMachine(String id) 메서드 사용
        StateMachine<MfaState, MfaEvent> stateMachine = stateMachineFactory.getStateMachine(machineId);

        // 기본 리스너 등록
        stateMachine.addStateListener(new MfaStateChangeLogger());

        return stateMachine;
    }

    @Override
    public StateMachine<MfaState, MfaEvent> restoreStateMachine(String machineId, MfaState state) {
        log.debug("Restoring State Machine {} to state {}", machineId, state);

        StateMachine<MfaState, MfaEvent> stateMachine = createStateMachine(machineId);

        // Spring State Machine 4.0.0에서는 직접적인 상태 설정이 제한적
        // Persister를 통해 복원하거나 특별한 이벤트를 사용해야 함

        return stateMachine;
    }

    /**
     * 상태 변경 로거 (내부 클래스)
     */
    private static class MfaStateChangeLogger extends StateMachineListenerAdapter<MfaState, MfaEvent> {
        @Override
        public void stateChanged(org.springframework.statemachine.state.State<MfaState, MfaEvent> from,
                                 org.springframework.statemachine.state.State<MfaState, MfaEvent> to) {
            log.info("State changed from {} to {}",
                    from != null ? from.getId() : "NONE",
                    to != null ? to.getId() : "NONE");
        }
    }
}
