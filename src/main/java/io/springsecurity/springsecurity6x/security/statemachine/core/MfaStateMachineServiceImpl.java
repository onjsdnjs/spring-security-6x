package io.springsecurity.springsecurity6x.security.statemachine.core;

import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.MfaEventAdapter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.Message;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.persist.StateMachinePersister;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * MFA State Machine 서비스 구현체 (Spring State Machine 4.0.0)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class MfaStateMachineServiceImpl implements MfaStateMachineService {

    private final MfaStateMachineFactory stateMachineFactory;
    private final StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister;
    private final FactorContextStateAdapter contextAdapter;
    private final MfaEventAdapter eventAdapter;
    private final ContextPersistence contextPersistence;
    private final MfaEventPublisher eventPublisher;

    // 활성 State Machine 추적
    private final Map<String, StateMachine<MfaState, MfaEvent>> activeMachines = new ConcurrentHashMap<>();

    @Override
    public boolean sendEvent(String sessionId, MfaEvent event, FactorContext context) {
        log.debug("Sending event {} for session {}", event, sessionId);

        try {
            StateMachine<MfaState, MfaEvent> stateMachine = acquireStateMachine(sessionId, context);

            // FactorContext를 State Machine 변수로 동기화
            Map<Object, Object> variables = contextAdapter.toStateMachineVariables(context);
            variables.forEach((key, value) ->
                    stateMachine.getExtendedState().getVariables().put(key, value)
            );

            // 이벤트 메시지 생성 및 전송
            Message<MfaEvent> message = eventAdapter.toStateMachineMessage(event, context);
            boolean result = stateMachine.sendEvent(message);

            if (result) {
                // State Machine 상태를 FactorContext로 역동기화
                updateFactorContextFromStateMachine(stateMachine, context);

                // 상태 저장
                stateMachinePersister.persist(stateMachine, sessionId);

                // 이벤트 발행
                eventPublisher.publishEvent(event, context, sessionId);

                log.info("Event {} successfully processed for session {}. New state: {}",
                        event, sessionId, stateMachine.getState().getId());
            } else {
                log.warn("Event {} was not accepted in current state {} for session {}",
                        event, stateMachine.getState().getId(), sessionId);
            }

            return result;

        } catch (Exception e) {
            log.error("Error processing event {} for session {}: {}", event, sessionId, e.getMessage(), e);
            return false;
        }
    }

    @Override
    public MfaState getCurrentState(String sessionId) {
        try {
            StateMachine<MfaState, MfaEvent> stateMachine = activeMachines.get(sessionId);
            if (stateMachine != null) {
                return stateMachine.getState().getId();
            }

            // 활성 머신이 없으면 persister에서 읽기 시도
            StateMachine<MfaState, MfaEvent> restoredMachine = stateMachineFactory.createStateMachine(sessionId);
            stateMachinePersister.restore(restoredMachine, sessionId);
            return restoredMachine.getState().getId();

        } catch (Exception e) {
            log.error("Error getting current state for session {}: {}", sessionId, e.getMessage());
            return MfaState.NONE;
        }
    }

    @Override
    public StateMachine<MfaState, MfaEvent> getStateMachine(String sessionId) {
        return activeMachines.get(sessionId);
    }

    @Override
    public void initializeStateMachine(String sessionId, FactorContext initialContext) {
        log.info("Initializing State Machine for session {}", sessionId);

        try {
            // 기존 머신이 있으면 제거
            releaseStateMachine(sessionId);

            // 새 State Machine 생성
            StateMachine<MfaState, MfaEvent> stateMachine = stateMachineFactory.createStateMachine(sessionId);

            // 초기 컨텍스트 설정
            if (initialContext != null) {
                Map<Object, Object> variables = contextAdapter.toStateMachineVariables(initialContext);
                variables.forEach((key, value) ->
                        stateMachine.getExtendedState().getVariables().put(key, value)
                );
            }

            // State Machine 시작
            stateMachine.start();

            // 활성 머신으로 등록
            activeMachines.put(sessionId, stateMachine);

            // 초기 상태 저장
            stateMachinePersister.persist(stateMachine, sessionId);

            log.info("State Machine initialized for session {} with state {}",
                    sessionId, stateMachine.getState().getId());

        } catch (Exception e) {
            log.error("Error initializing State Machine for session {}: {}", sessionId, e.getMessage(), e);
            throw new RuntimeException("Failed to initialize State Machine", e);
        }
    }

    @Override
    public void releaseStateMachine(String sessionId) {
        log.debug("Releasing State Machine for session {}", sessionId);

        StateMachine<MfaState, MfaEvent> stateMachine = activeMachines.remove(sessionId);
        if (stateMachine != null) {
            try {
                // 최종 상태 저장
                stateMachinePersister.persist(stateMachine, sessionId);

                // State Machine 정지
                stateMachine.stop();

                log.info("State Machine released for session {}", sessionId);
            } catch (Exception e) {
                log.error("Error releasing State Machine for session {}: {}", sessionId, e.getMessage());
            }
        }
    }

    /**
     * State Machine 획득 (없으면 복원 또는 생성)
     */
    private StateMachine<MfaState, MfaEvent> acquireStateMachine(String sessionId, FactorContext context)
            throws Exception {

        StateMachine<MfaState, MfaEvent> stateMachine = activeMachines.get(sessionId);

        if (stateMachine == null) {
            // 새로 생성
            stateMachine = stateMachineFactory.createStateMachine(sessionId);

            try {
                // Persister에서 복원 시도
                stateMachinePersister.restore(stateMachine, sessionId);
                log.debug("State Machine restored from persistence for session {}", sessionId);
            } catch (Exception e) {
                // 복원 실패 시 새로 시작
                log.debug("No persisted state found for session {}, starting fresh", sessionId);

                if (context != null) {
                    Map<Object, Object> variables = contextAdapter.toStateMachineVariables(context);
                    StateMachine<MfaState, MfaEvent> finalStateMachine = stateMachine;
                    variables.forEach((key, value) ->
                            finalStateMachine.getExtendedState().getVariables().put(key, value)
                    );
                }
            }

            // State Machine 시작 (아직 시작되지 않은 경우)
            if (!stateMachine.hasStateMachineError()) {
                stateMachine.start();
            }

            activeMachines.put(sessionId, stateMachine);
        }

        return stateMachine;
    }

    /**
     * StateMachine 상태를 FactorContext로 업데이트
     */
    private void updateFactorContextFromStateMachine(StateMachine<MfaState, MfaEvent> stateMachine,
                                                     FactorContext context) {
        // 현재 상태
        MfaState currentState = stateMachine.getState().getId();
        context.changeState(currentState);

        // Extended State 변수들
        Map<Object, Object> variables = stateMachine.getExtendedState().getVariables();

        // 필요한 변수들 업데이트
        Integer retryCount = (Integer) variables.get("retryCount");
        if (retryCount != null) {
            context.setRetryCount(retryCount);
        }

        String lastError = (String) variables.get("lastError");
        if (lastError != null) {
            context.setLastError(lastError);
        }

        String currentStepId = (String) variables.get("currentStepId");
        if (currentStepId != null) {
            context.setCurrentStepId(currentStepId);
        }
    }
}
