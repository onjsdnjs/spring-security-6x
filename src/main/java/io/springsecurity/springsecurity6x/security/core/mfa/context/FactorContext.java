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
@Setter // Lombok Setter를 사용하여 모든 non-final 필드에 대한 setter 자동 생성
@Slf4j
public class FactorContext implements Serializable {

    private static final long serialVersionUID = 2024051704L;

    private final String mfaSessionId;
    private final AtomicReference<MfaState> currentState;
    private final AtomicInteger version = new AtomicInteger(0);

    private Authentication primaryAuthentication;
    private String username;

    private final Map<AuthType, FactorAuthenticationOptions> factorSpecificOptions;

    private boolean mfaRequired = false;
    private Set<AuthType> registeredMfaFactors;
    private AuthType preferredAutoAttemptFactor;

    private boolean autoAttemptFactorSucceeded = false; // Setter 필요
    private boolean autoAttemptFactorSkippedOrFailed = false; // Setter 필요

    private AuthType currentProcessingFactor; // Setter 필요 (이미 @Setter로 생성됨)
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
    }

    public FactorContext(Authentication primaryAuthentication) {
        this(primaryAuthentication, Collections.emptyMap());
    }

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
        }
    }

    public boolean compareAndSetState(MfaState expect, MfaState update) {
        boolean success = this.currentState.compareAndSet(expect, update);
        if (success) {
            this.version.incrementAndGet();
            this.lastActivityTimestamp = Instant.now();
        }
        return success;
    }

    public FactorAuthenticationOptions getCurrentFactorOptions() {
        if (this.currentProcessingFactor == null) {
            return null;
        }
        return this.factorSpecificOptions.get(this.currentProcessingFactor);
    }

    public void setAllFactorSpecificOptions(Map<AuthType, FactorAuthenticationOptions> factorOptionsMap) {
        this.factorSpecificOptions.clear();
        if (factorOptionsMap != null) {
            this.factorSpecificOptions.putAll(factorOptionsMap);
        }
    }

    public int incrementAttemptCountForCurrentFactor() {
        if (this.currentProcessingFactor == null) return 0;
        int newCount = factorAttemptCounts.merge(this.currentProcessingFactor, 1, Integer::sum);
        this.lastActivityTimestamp = Instant.now();
        return newCount;
    }

    public void recordAttempt(AuthType factorType, boolean success, String detail) {
        this.mfaAttemptHistory.add(new MfaAttemptDetail(factorType, success, detail));
        this.lastActivityTimestamp = Instant.now();
    }

    public Object getChallengePayload(String key) {
        return this.currentChallengePayload.get(key);
    }

    @Getter // MfaAttemptDetail 내부 필드에 대한 getter
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




