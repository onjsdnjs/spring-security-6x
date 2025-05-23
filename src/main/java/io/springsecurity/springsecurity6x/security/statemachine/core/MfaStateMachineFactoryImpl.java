package io.springsecurity.springsecurity6x.security.statemachine.core;

import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.persist.StateMachinePersister;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * MFA State Machine 생성 및 복원을 담당하는 팩토리 구현체
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MfaStateMachineFactoryImpl implements MfaStateMachineFactory {

    private final StateMachineFactory<MfaState, MfaEvent> stateMachineFactory;
    private final StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister;

    @Override
    public StateMachine<MfaState, MfaEvent> createStateMachine(String machineId) {
        log.debug("Creating new state machine with ID: {}", machineId);

        try {
            // Spring StateMachineFactory를 통해 새 인스턴스 생성
            StateMachine<MfaState, MfaEvent> stateMachine = stateMachineFactory.getStateMachine(machineId);

            // 상태 머신 시작
            stateMachine.start();

            log.info("State machine created and started with ID: {}", machineId);
            return stateMachine;

        } catch (Exception e) {
            log.error("Failed to create state machine with ID: {}", machineId, e);
            throw new RuntimeException("Failed to create state machine", e);
        }
    }

    @Override
    public StateMachine<MfaState, MfaEvent> createStateMachine() {
        // 랜덤 ID로 새 상태 머신 생성
        String machineId = generateMachineId();
        return createStateMachine(machineId);
    }

    @Override
    public StateMachine<MfaState, MfaEvent> restoreStateMachine(String machineId) {
        log.debug("Attempting to restore state machine with ID: {}", machineId);

        try {
            // 새 상태 머신 인스턴스 생성
            StateMachine<MfaState, MfaEvent> stateMachine = stateMachineFactory.getStateMachine(machineId);

            // Persister를 통해 저장된 상태 복원
            try {
                stateMachinePersister.restore(stateMachine, machineId);
                log.info("Successfully restored state machine with ID: {}", machineId);
            } catch (Exception e) {
                // 복원 실패 시 새 상태 머신으로 시작
                log.warn("Failed to restore state machine with ID: {}, starting fresh", machineId);
                stateMachine.start();
            }

            // 상태 머신이 시작되지 않은 경우 시작
            if (!stateMachine.isComplete() && stateMachine.getState() == null) {
                stateMachine.start();
            }

            return stateMachine;

        } catch (Exception e) {
            log.error("Failed to restore state machine with ID: {}", machineId, e);
            throw new RuntimeException("Failed to restore state machine", e);
        }
    }

    @Override
    public void releaseStateMachine(String machineId) {
        log.debug("Releasing state machine with ID: {}", machineId);

        try {
            // 상태 머신 정리 작업
            // 필요한 경우 추가적인 정리 로직 구현
            // 예: 캐시에서 제거, 리소스 해제 등

            log.info("State machine released with ID: {}", machineId);
        } catch (Exception e) {
            log.error("Error releasing state machine with ID: {}", machineId, e);
        }
    }

    /**
     * 상태 머신 ID 생성
     */
    private String generateMachineId() {
        return "MFA-" + UUID.randomUUID().toString();
    }

    /**
     * 상태 머신이 유효한지 확인
     */
    public boolean isStateMachineValid(StateMachine<MfaState, MfaEvent> stateMachine) {
        if (stateMachine == null) {
            return false;
        }

        // 상태 머신이 에러 상태인지 확인
        if (stateMachine.hasStateMachineError()) {
            log.warn("State machine {} has error", stateMachine.getId());
            return false;
        }

        // 현재 상태가 유효한지 확인
        if (stateMachine.getState() == null) {
            log.warn("State machine {} has null state", stateMachine.getId());
            return false;
        }

        return true;
    }
}