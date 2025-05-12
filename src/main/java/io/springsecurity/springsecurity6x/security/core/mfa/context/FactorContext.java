package io.springsecurity.springsecurity6x.security.core.mfa.context;

import io.springsecurity.springsecurity6x.security.core.mfa.RecoveryConfig;
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
    private final Map<String,Object> attributes = new HashMap<>();
    private RecoveryConfig recoveryConfig;
    private int version = 0;

    public String sessionId() { return sessionId; }
    public void sessionId(String sessionId) { this.sessionId = sessionId; }

    public MfaState currentState() { return currentState; }
    public void currentState(MfaState state) { this.currentState = state; }

    public List<Object> successes() { return successes; }
    public Map<String,Integer> retryCounts() { return retryCounts; }
    public Map<String,Object> attributes() { return attributes; }

    public RecoveryConfig recoveryConfig() {
        return recoveryConfig;
    }
    public void recoveryConfig(RecoveryConfig recoveryConfig) {
        this.recoveryConfig = recoveryConfig;
    }

    public int version() { return version; }
    public void incrementVersion() { this.version++; }
}


