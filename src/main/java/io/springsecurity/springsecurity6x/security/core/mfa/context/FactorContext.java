package io.springsecurity.springsecurity6x.security.core.mfa.context;

import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

@Getter
@Slf4j
public class FactorContext implements Serializable {

    private static final long serialVersionUID = 20250520_01L; // 버전 업데이트

    private final String mfaSessionId;
    private final AtomicReference<MfaState> currentMfaState;
    private final AtomicInteger version = new AtomicInteger(0);

    private final Authentication primaryAuthentication;
    private final String username;

    @Setter private boolean mfaRequiredAsPerPolicy = false;
    @Setter private EnumSet<AuthType> registeredMfaFactors = EnumSet.noneOf(AuthType.class);
    @Setter @Nullable private AuthType currentProcessingFactor;
    private final Set<AuthType> completedMfaFactors = EnumSet.noneOf(AuthType.class);

    // 자동 인증 시도 관련 필드 추가
    @Setter @Nullable private AuthType preferredAutoAttemptFactor;
    @Setter private boolean autoAttemptFactorSkippedOrFailed = false;
    @Setter private boolean autoAttemptFactorSucceeded = false;

    private final Map<AuthType, Integer> factorAttemptCounts = new ConcurrentHashMap<>();
    private Instant lastActivityTimestamp;
    private final List<MfaAttemptDetail> mfaAttemptHistory = new CopyOnWriteArrayList<>();
    private final Map<String, Object> attributes = new ConcurrentHashMap<>();

    public FactorContext(Authentication primaryAuthentication) {
        Assert.notNull(primaryAuthentication, "PrimaryAuthentication cannot be null when creating FactorContext.");
        Assert.isTrue(primaryAuthentication.isAuthenticated(), "PrimaryAuthentication must be authenticated.");
        this.mfaSessionId = UUID.randomUUID().toString();
        this.primaryAuthentication = primaryAuthentication;
        this.username = primaryAuthentication.getName();
        this.currentMfaState = new AtomicReference<>(MfaState.PRIMARY_AUTHENTICATION_COMPLETED);
        this.lastActivityTimestamp = Instant.now();
        log.info("FactorContext created for user '{}'. Session ID: {}, Initial State: {}",
                this.username, mfaSessionId, this.currentMfaState.get());
    }

    public MfaState getCurrentState() {
        return currentMfaState.get();
    }

    public void changeState(MfaState newState) {
        Assert.notNull(newState, "New MfaState cannot be null.");
        MfaState oldState = this.currentMfaState.getAndSet(newState);
        if (oldState != newState) {
            this.version.incrementAndGet();
            updateLastActivityTimestamp(); // 내부 호출로 변경
            log.info("FactorContext (ID: {}) state changed: {} -> {}", mfaSessionId, oldState, newState);
        }
    }

    public boolean compareAndSetState(MfaState expect, MfaState update) {
        Assert.notNull(expect, "Expected MfaState cannot be null.");
        Assert.notNull(update, "Update MfaState cannot be null.");
        boolean success = this.currentMfaState.compareAndSet(expect, update);
        if (success) {
            this.version.incrementAndGet();
            updateLastActivityTimestamp(); // 내부 호출로 변경
            log.info("FactorContext (ID: {}) state compareAndSet: {} -> {}. Success: {}", mfaSessionId, expect, update, true);
        } else {
            log.warn("FactorContext (ID: {}) state compareAndSet FAILED. Expected: {}, Actual: {}, UpdateTo: {}", mfaSessionId, expect, getCurrentState(), update);
        }
        return success;
    }

    public void addCompletedFactor(AuthType factorType) {
        if (factorType != null) {
            synchronized (this.completedMfaFactors) {
                this.completedMfaFactors.add(factorType);
            }
            updateLastActivityTimestamp(); // 내부 호출로 변경
            log.debug("FactorContext (ID: {}): Factor {} marked as completed.", mfaSessionId, factorType);
        }
    }

    public int incrementAttemptCount(@Nullable AuthType factorType) {
        if (factorType == null) {
            log.warn("FactorContext (ID: {}): Attempted to increment attempt count for a null factorType.", mfaSessionId);
            return 0;
        }
        int newCount = factorAttemptCounts.compute(factorType, (key, val) -> (val == null) ? 1 : val + 1);
        updateLastActivityTimestamp(); // 내부 호출로 변경
        log.debug("FactorContext (ID: {}): Attempt count for {} incremented to {}.", mfaSessionId, factorType, newCount);
        return newCount;
    }

    public int getAttemptCount(@Nullable AuthType factorType) {
        if (factorType == null) return 0;
        return factorAttemptCounts.getOrDefault(factorType, 0);
    }

    public void recordAttempt(@Nullable AuthType factorType, boolean success, String detail) {
        this.mfaAttemptHistory.add(new MfaAttemptDetail(factorType, success, detail));
        updateLastActivityTimestamp(); // 내부 호출로 변경
        log.info("FactorContext (ID: {}): MFA attempt recorded: Factor={}, Success={}, Detail='{}'", mfaSessionId, factorType, success, detail);
    }

    @Nullable
    public Object getAttribute(String key) {
        return this.attributes.get(key);
    }

    public void setAttribute(String key, Object value) {
        Assert.hasText(key, "Attribute key cannot be empty or null.");
        if (value == null) {
            this.attributes.remove(key);
            log.debug("FactorContext (ID: {}): Attribute removed: Key='{}'", mfaSessionId, key);
        } else {
            this.attributes.put(key, value);
            log.debug("FactorContext (ID: {}): Attribute set: Key='{}', Value type='{}'", mfaSessionId, key, value.getClass().getSimpleName());
        }
        updateLastActivityTimestamp(); // 내부 호출로 변경
    }

    // 추가된 getter 메소드들
    @Nullable
    public AuthType getPreferredAutoAttemptFactor() {
        return preferredAutoAttemptFactor;
    }

    public boolean isAutoAttemptFactorSkippedOrFailed() {
        return autoAttemptFactorSkippedOrFailed;
    }

    public boolean isAutoAttemptFactorSucceeded() {
        return autoAttemptFactorSucceeded;
    }

    // 공개 메소드로 변경하여 OttStateHandler 등에서 호출 가능하도록 함
    public void updateLastActivityTimestamp() {
        this.lastActivityTimestamp = Instant.now();
        log.trace("FactorContext (ID: {}) lastActivityTimestamp updated to: {}", mfaSessionId, this.lastActivityTimestamp);
    }

    @Getter
    public static class MfaAttemptDetail implements Serializable {
        private static final long serialVersionUID = 20250520_02L; // 버전 업데이트
        @Nullable
        private final AuthType factorType;
        private final boolean success;
        private final Instant timestamp;
        private final String detail;

        public MfaAttemptDetail(@Nullable AuthType factorType, boolean success, String detail) {
            this.factorType = factorType;
            this.success = success;
            this.timestamp = Instant.now();
            this.detail = detail;
        }
    }
}




