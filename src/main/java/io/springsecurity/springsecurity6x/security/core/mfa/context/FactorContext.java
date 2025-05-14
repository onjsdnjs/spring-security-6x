package io.springsecurity.springsecurity6x.security.core.mfa.context;

import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;

import java.io.Serializable;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

@Getter
@Setter
@Slf4j
public class FactorContext implements Serializable {

    private static final long serialVersionUID = 2024051601L; // 예시 Serializable UID

    private final String mfaSessionId;
    private final AtomicReference<MfaState> currentState;
    private final AtomicInteger version = new AtomicInteger(0);

    private Authentication primaryAuthentication;
    private String username;

    private final Map<AuthType, FactorAuthenticationOptions> factorSpecificOptions;

    // --- MFA 정책 관련 필드 ---
    private boolean mfaRequired = false; // MFA 필요 여부 플래그
    private Set<AuthType> registeredMfaFactors; // 사용자가 등록한 MFA 수단
    private AuthType preferredAutoAttemptFactor; // 정책에 의해 결정된 자동 시도 Factor
    // ---

    private boolean autoAttemptFactorSucceeded = false;
    private boolean autoAttemptFactorSkippedOrFailed = false;

    private AuthType currentProcessingFactor;
    private final Map<AuthType, Integer> factorAttemptCounts = new ConcurrentHashMap<>();
    private Instant lastActivityTimestamp;

    private final Map<String, Object> currentChallengePayload = new ConcurrentHashMap<>();
    private final List<MfaAttemptDetail> mfaAttemptHistory = new CopyOnWriteArrayList<>();
    private final Map<String, Object> attributes = new ConcurrentHashMap<>();

    public FactorContext(Authentication primaryAuthentication, Map<AuthType, FactorAuthenticationOptions> factorSpecificOptionsMap) {
        this.mfaSessionId = UUID.randomUUID().toString();
        this.primaryAuthentication = primaryAuthentication;

        if (primaryAuthentication != null) {
            this.username = primaryAuthentication.getName();
            this.currentState = new AtomicReference<>(MfaState.PRIMARY_AUTHENTICATION_COMPLETED);
        } else {
            this.username = null;
            this.currentState = new AtomicReference<>(MfaState.AWAITING_MFA_FACTOR_SELECTION);
        }
        this.factorSpecificOptions = (factorSpecificOptionsMap != null) ? new ConcurrentHashMap<>(factorSpecificOptionsMap) : new ConcurrentHashMap<>();
        this.lastActivityTimestamp = Instant.now();
        log.debug("[FactorContext] Created. Session ID: {}, Initial State: {}, Username: {}, Loaded {} factor options.",
                this.mfaSessionId, this.currentState.get(), this.username, this.factorSpecificOptions.size());
    }

    public FactorContext(Authentication primaryAuthentication) {
        this(primaryAuthentication, Collections.emptyMap());
    }

    // --- mfaRequired 필드에 대한 getter 및 setter ---
    /**
     * 현재 사용자에 대해 MFA가 요구되는지 여부를 반환합니다.
     * 이 값은 MfaPolicyProvider 등에 의해 FactorContext 초기화 시점에 설정되어야 합니다.
     * @return MFA가 요구되면 true, 그렇지 않으면 false.
     */
    public boolean isMfaRequired() {
        return mfaRequired;
    }

    public void setMfaRequired(boolean mfaRequired) {
        this.mfaRequired = mfaRequired;
    }
    // ---

    public MfaState getCurrentState() {
        return currentState.get();
    }

    public int getVersion() {
        return version.get();
    }

    public void changeState(MfaState newState) {
        MfaState oldState = this.currentState.getAndSet(newState);
        if (oldState != newState) {
            this.version.incrementAndGet();
            this.lastActivityTimestamp = Instant.now();
            log.debug("[FactorContext] State changed from {} to {}. Session ID: {}", oldState, newState, this.mfaSessionId);
        }
    }

    public boolean compareAndSetState(MfaState expect, MfaState update) {
        boolean success = this.currentState.compareAndSet(expect, update);
        if (success) {
            this.version.incrementAndGet();
            this.lastActivityTimestamp = Instant.now();
            log.debug("[FactorContext] State compareAndSet from {} to {} successful. Session ID: {}", expect, update, this.mfaSessionId);
        } else {
            log.warn("[FactorContext] State compareAndSet from {} to {} failed. Current state is {}. Session ID: {}", expect, update, this.currentState.get(), this.mfaSessionId);
        }
        return success;
    }

    public FactorAuthenticationOptions getCurrentFactorOptions() {
        if (this.currentProcessingFactor == null) {
            log.trace("[FactorContext] currentProcessingFactor is null, cannot get specific options. Session ID: {}", this.mfaSessionId);
            return null;
        }
        if (this.factorSpecificOptions == null) {
            log.warn("[FactorContext] factorSpecificOptions map is null. Session ID: {}", this.mfaSessionId);
            return null;
        }
        FactorAuthenticationOptions options = this.factorSpecificOptions.get(this.currentProcessingFactor);
        if (options == null) {
            log.warn("[FactorContext] No specific options found for currentProcessingFactor: {} in map. Session ID: {}",
                    this.currentProcessingFactor, this.mfaSessionId);
        }
        return options;
    }

    public void setAllFactorSpecificOptions(Map<AuthType, FactorAuthenticationOptions> factorOptionsMap) {
        this.factorSpecificOptions.clear();
        if (factorOptionsMap != null) {
            this.factorSpecificOptions.putAll(factorOptionsMap);
            log.debug("[FactorContext] Replaced factorSpecificOptions with {} entries. Session ID: {}", factorOptionsMap.size(), this.mfaSessionId);
        } else {
            log.warn("[FactorContext] Cleared factorSpecificOptions as input map was null. Session ID: {}", this.mfaSessionId);
        }
    }
    // ... (기타 필요한 메소드들은 여기에 계속됩니다) ...
    public void addChallengePayload(String key, Object value) {
        this.currentChallengePayload.put(key, value);
    }

    public Object getChallengePayload(String key) {
        return this.currentChallengePayload.get(key);
    }
    public void recordAttempt(AuthType factorType, boolean success, String detail) {
        this.mfaAttemptHistory.add(new MfaAttemptDetail(factorType, success, detail));
        this.lastActivityTimestamp = Instant.now();
    }

    @SuppressWarnings("unchecked")
    public <T> T getAttributeOrDefault(String key, T defaultValue) {
        if (attributes == null) {
            return defaultValue;
        }
        Object value = attributes.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (defaultValue != null && !defaultValue.getClass().isInstance(value)) {
            log.warn("[FactorContext] Attribute '{}' is of type {} but expected type {}. Returning default. Session ID: {}",
                    key, value.getClass().getName(), defaultValue.getClass().getName(), this.mfaSessionId);
            return defaultValue;
        }
        try {
            return (T) value;
        } catch (ClassCastException e) {
            log.warn("[FactorContext] Attribute '{}' failed to cast to expected type {}. Value: '{}'. Session ID: {}",
                    key, defaultValue != null ? defaultValue.getClass().getName() : "unknown", value, this.mfaSessionId, e);
            return defaultValue;
        }
    }


    @Getter
    public static class MfaAttemptDetail implements Serializable {
        private static final long serialVersionUID = 2024051401L;
        private final AuthType factorType;
        private final boolean success;
        private final Instant timestamp;
        private final String detail;

        public MfaAttemptDetail(AuthType factorType, boolean success, String detail) {
            this.factorType = factorType;
            this.success = success;
            this.timestamp = Instant.now();
            this.detail = detail;
        }
    }
}



