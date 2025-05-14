package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.enums.MfaState; // 새로운 MfaState 사용
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

public class StateHandlerRegistry {
    private final Map<MfaState, MfaStateHandler> registry = new EnumMap<>(MfaState.class);

    public StateHandlerRegistry(List<MfaStateHandler> handlers) {
        if (handlers == null) {
            throw new IllegalArgumentException("Handlers list cannot be null.");
        }
        for (MfaStateHandler handler : handlers) {
            if (handler == null) continue; // Null 핸들러 방지
            // 새로운 MfaState enum의 모든 값을 순회하며 supports 여부 확인
            for (MfaState state : MfaState.values()) {
                try {
                    if (handler.supports(state)) {
                        // 하나의 상태에 여러 핸들러가 매핑되는 것을 방지하거나, 정책을 정해야 함.
                        // 여기서는 마지막으로 등록된 핸들러가 우선권을 가짐.
                        if (registry.containsKey(state)) {
                            // 로깅 또는 경고 처리: 이미 해당 상태에 대한 핸들러가 등록되어 있음
                            System.err.println("Warning: Overwriting handler for MfaState " + state +
                                    ". Old: " + registry.get(state).getClass().getSimpleName() +
                                    ", New: " + handler.getClass().getSimpleName());
                        }
                        registry.put(state, handler);
                    }
                } catch (Exception e) {
                    // supports 메소드에서 예외 발생 시 로깅 또는 오류 처리
                    System.err.println("Error while checking support for state " + state +
                            " with handler " + handler.getClass().getSimpleName() + ": " + e.getMessage());
                }
            }
        }
    }

    public MfaStateHandler get(MfaState state) {
        return registry.get(state);
    }
}
