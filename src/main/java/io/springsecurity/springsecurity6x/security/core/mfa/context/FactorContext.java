package io.springsecurity.springsecurity6x.security.core.mfa.context;

import io.springsecurity.springsecurity6x.security.enums.MfaState;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FactorContext {
    private String sessionId;
    private MfaState currentState = MfaState.INIT;
    private final List<Object> successes = new ArrayList<>();
    private final Map<String,Integer> retryCounts = new HashMap<>();

    // ← 여기에 attributes 필드 추가
    private final Map<String,Object> attributes = new HashMap<>();

    private int version = 0;

    // … 기존 생성자/필드 접근자 …

    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }

    public MfaState getCurrentState() { return currentState; }
    public void setCurrentState(MfaState state) { this.currentState = state; }

    public List<Object> getSuccesses() { return successes; }
    public Map<String,Integer> getRetryCounts() { return retryCounts; }

    // ← attributes getter
    public Map<String,Object> getAttributes() {
        return attributes;
    }

    public int getVersion() { return version; }
    public void incrementVersion() { this.version++; }
}

