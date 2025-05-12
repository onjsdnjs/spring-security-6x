package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.enums.MfaState;
import jakarta.annotation.PostConstruct;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 상태별 핸들러를 ServiceLoader 기반으로 로드하고 관리하는 POJO Registry
 */
public class StateHandlerRegistry {
    private final Map<MfaState, MfaStateHandler> registry = new EnumMap<>(MfaState.class);

    /**
     * 생성자에서 핸들러 리스트를 직접 받아 초기화합니다.
     */
    public StateHandlerRegistry(List<MfaStateHandler> handlers) {
        for (MfaStateHandler handler : handlers) {
            for (MfaState state : MfaState.values()) {
                if (handler.supports(state)) {
                    registry.put(state, handler);
                }
            }
        }
    }

    /**
     * 주어진 상태에 맞는 핸들러 반환
     */
    public MfaStateHandler get(MfaState state) {
        return registry.get(state);
    }
}
