package io.springsecurity.springsecurity6x.security.statemachine.core;

import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.StateMachinePersist;
import org.springframework.statemachine.persist.AbstractStateMachinePersister;
import org.springframework.statemachine.persist.StateMachinePersister;
import org.springframework.statemachine.support.DefaultStateMachineContext;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-Memory State Machine Persister 구현체 (Spring State Machine 4.0.0)
 */
@Slf4j
@Component
public class MfaStateMachinePersisterImpl implements MfaStateMachinePersister,
        StateMachinePersist<MfaState, MfaEvent, String> {

    // 임시 In-Memory 저장소
    private final Map<String, StateMachineContext<MfaState, MfaEvent>> storage = new ConcurrentHashMap<>();

    private static final String KEY_PREFIX = "mfa:statemachine:";

    @Override
    public void write(StateMachineContext<MfaState, MfaEvent> context, String contextObj) throws Exception {
        String key = KEY_PREFIX + contextObj;
        log.debug("Persisting State Machine context for key: {}", key);

        storage.put(key, context);

        log.debug("State Machine context persisted. State: {}, Event: {}",
                context.getState(), context.getEvent());
    }

    @Override
    public StateMachineContext<MfaState, MfaEvent> read(String contextObj) throws Exception {
        String key = KEY_PREFIX + contextObj;
        log.debug("Reading State Machine context for key: {}", key);

        StateMachineContext<MfaState, MfaEvent> context = storage.get(key);

        if (context != null) {
            log.debug("State Machine context found. State: {}, Event: {}",
                    context.getState(), context.getEvent());
        } else {
            log.debug("No State Machine context found for key: {}", key);
        }

        return context;
    }

    /**
     * 컨텍스트 삭제 (추가 메서드)
     */
    public void delete(String contextObj) {
        String key = KEY_PREFIX + contextObj;
        log.debug("Deleting State Machine context for key: {}", key);

        storage.remove(key);
    }
}