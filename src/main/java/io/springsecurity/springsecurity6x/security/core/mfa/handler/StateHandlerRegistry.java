package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.enums.MfaState;
import jakarta.annotation.PostConstruct;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class StateHandlerRegistry {
    private final List<MfaStateHandler> handlers;
    private final Map<MfaState, MfaStateHandler> map = new ConcurrentHashMap<>();

    public StateHandlerRegistry(List<MfaStateHandler> handlers) {
        this.handlers = handlers;
    }

    @PostConstruct
    public void init() {
        for (MfaStateHandler h : handlers) {
            for (MfaState s : MfaState.values()) {
                if (h.supports(s)) {
                    map.put(s, h);
                }
            }
        }
    }

    public MfaStateHandler get(MfaState state) {
        return map.get(state);
    }
}
