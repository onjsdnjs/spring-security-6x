package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.enums.MfaState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class StateHandlerRegistry {
    private static final Logger log = LoggerFactory.getLogger(StateHandlerRegistry.class);
    private final Map<MfaState, MfaStateHandler> registry = new EnumMap<>(MfaState.class);

    public StateHandlerRegistry(List<MfaStateHandler> handlers) {
        Objects.requireNonNull(handlers, "Handlers list cannot be null."); // Null 체크 강화

        for (MfaStateHandler handler : handlers) {
            if (handler == null) {
                log.warn("Null MfaStateHandler instance found in the provided list, skipping.");
                continue;
            }
            for (MfaState state : MfaState.values()) { // 모든 MfaState 값 순회
                try {
                    if (handler.supports(state)) {
                        if (registry.containsKey(state)) {
                            log.warn("Overwriting handler for MfaState {}. Old: {}, New: {}",
                                    state, registry.get(state).getClass().getSimpleName(), handler.getClass().getSimpleName());
                        }
                        registry.put(state, handler);
                        log.debug("Registered handler {} for MfaState {}", handler.getClass().getSimpleName(), state);
                    }
                } catch (Exception e) {
                    log.error("Error while invoking supports() for state {} with handler {}: {}",
                            state, handler.getClass().getSimpleName(), e.getMessage(), e);
                }
            }
        }
    }

    public MfaStateHandler get(MfaState state) {
        MfaStateHandler handler = registry.get(state);
        // 핸들러가 없는 경우 null을 반환하며, 호출하는 쪽에서 처리 (예: InvalidTransitionException 발생)
        if (handler == null) {
            log.warn("No MfaStateHandler found for MfaState: {}. This might lead to an InvalidTransitionException if not handled by the caller.", state);
        }
        return handler;
    }
}
