package io.springsecurity.springsecurity6x.security.core.mfa.context;

import io.springsecurity.springsecurity6x.security.core.mfa.RecoveryConfig;
import io.springsecurity.springsecurity6x.security.enums.MfaState;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public class FactorContext {

    private String sessionId;
    private final AtomicReference<MfaState> currentState = new AtomicReference<>(MfaState.INIT);
    private final List<Object> successes = new CopyOnWriteArrayList<>();
    private final Map<String, Integer> retryCounts = new ConcurrentHashMap<>();;
    private final Map<String, Object> attributes = new ConcurrentHashMap<>();;
    private RecoveryConfig recoveryConfig;
    private final AtomicInteger version = new AtomicInteger(0);

    private static final List<MfaState> DEFAULT_FLOW = List.of(
            MfaState.INIT,
            MfaState.FORM_CHALLENGE, MfaState.FORM_SUBMITTED,
            MfaState.REST_CHALLENGE, MfaState.REST_SUBMITTED,
            MfaState.OTT_CHALLENGE, MfaState.OTT_SUBMITTED,
            MfaState.PASSKEY_CHALLENGE, MfaState.PASSKEY_SUBMITTED,
            MfaState.TOKEN_ISSUANCE
    );


    public String sessionId() {
        return sessionId;
    }

    public void sessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public MfaState currentState() {
        return currentState.get();
    }

    public void currentState(MfaState state) {
        currentState.set(state);
    }

    public boolean tryTransition(MfaState expected, MfaState next) {
        return !currentState.compareAndSet(expected, next);
    }

    public List<Object> successes() {
        return successes;
    }

    public Map<String, Integer> retryCounts() {
        return retryCounts;
    }

    public Map<String, Object> attributes() {
        return attributes;
    }

    public RecoveryConfig recoveryConfig() {
        return recoveryConfig;
    }

    public void recoveryConfig(RecoveryConfig recoveryConfig) {
        this.recoveryConfig = recoveryConfig;
    }

    public int version() {
        return version.get();
    }

    public void version(int v) {
        version.set(v);
    }

    public void incrementVersion() {
        version.incrementAndGet();
    }

    public boolean isLastStep() {
        MfaState state = currentState();
        int idx = DEFAULT_FLOW.indexOf(state);

        if (idx == -1 || idx == DEFAULT_FLOW.size() - 1) {
            return true;
        }

        // 다음 상태가 TOKEN_ISSUANCE 이면 마지막 단계로 간주
        MfaState next = DEFAULT_FLOW.get(idx + 1);
        return next == MfaState.TOKEN_ISSUANCE;
    }
}


