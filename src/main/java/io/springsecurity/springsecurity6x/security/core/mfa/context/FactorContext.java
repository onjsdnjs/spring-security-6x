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

    private static final long serialVersionUID = 20250519_03L; // 버전 업데이트

    private final String mfaSessionId;
    private final AtomicReference<MfaState> currentMfaState;
    private final AtomicInteger version = new AtomicInteger(0);

    private final Authentication primaryAuthentication; // 1차 인증 성공 객체
    private final String username; // primaryAuthentication에서 추출

    // MFA 정책 및 진행 상태 관련 필드
    @Setter private boolean mfaRequiredAsPerPolicy = false;
    @Setter private EnumSet<AuthType> registeredMfaFactors = EnumSet.noneOf(AuthType.class);
    @Setter @Nullable private AuthType currentProcessingFactor; // 현재 사용자가 선택했거나 시스템이 다음에 처리할 Factor
    private final Set<AuthType> completedMfaFactors = EnumSet.noneOf(AuthType.class); // 동기화된 Set 사용 고려

    private final Map<AuthType, Integer> factorAttemptCounts = new ConcurrentHashMap<>();
    private Instant lastActivityTimestamp;
    private final List<MfaAttemptDetail> mfaAttemptHistory = new CopyOnWriteArrayList<>();
    private final Map<String, Object> attributes = new ConcurrentHashMap<>(); // 예: deviceId

    public FactorContext(Authentication primaryAuthentication) {
        Assert.notNull(primaryAuthentication, "PrimaryAuthentication cannot be null when creating FactorContext.");
        Assert.isTrue(primaryAuthentication.isAuthenticated(), "PrimaryAuthentication must be authenticated.");
        this.mfaSessionId = UUID.randomUUID().toString();
        this.primaryAuthentication = primaryAuthentication;
        this.username = primaryAuthentication.getName();
        // 초기 상태는 1차 인증 성공 직후로 명확히 설정 (호출하는 쪽에서 설정하는 것보다 여기서 기본값 지정)
        this.currentMfaState = new AtomicReference<>(MfaState.PRIMARY_AUTHENTICATION_COMPLETED);
        this.lastActivityTimestamp = Instant.now();
        log.info("FactorContext created for user '{}'. Session ID: {}, Initial State: {}",
                this.username, mfaSessionId, this.currentMfaState.get());
    }

    public MfaState getCurrentState() { // 메소드명 일관성 유지
        return currentMfaState.get();
    }

    // 상태 변경은 이 메소드를 통해서만 이루어지도록 캡슐화 강화 가능
    public void changeState(MfaState newState) {
        Assert.notNull(newState, "New MfaState cannot be null.");
        MfaState oldState = this.currentMfaState.getAndSet(newState);
        if (oldState != newState) {
            this.version.incrementAndGet();
            this.lastActivityTimestamp = Instant.now();
            log.info("FactorContext (ID: {}) state changed: {} -> {}", mfaSessionId, oldState, newState);
        }
    }

    public boolean compareAndSetState(MfaState expect, MfaState update) {
        Assert.notNull(expect, "Expected MfaState cannot be null.");
        Assert.notNull(update, "Update MfaState cannot be null.");
        boolean success = this.currentMfaState.compareAndSet(expect, update);
        if (success) {
            this.version.incrementAndGet();
            this.lastActivityTimestamp = Instant.now();
            log.info("FactorContext (ID: {}) state compareAndSet: {} -> {}. Success: {}", mfaSessionId, expect, update, true);
        } else {
            log.warn("FactorContext (ID: {}) state compareAndSet FAILED. Expected: {}, Actual: {}, UpdateTo: {}", mfaSessionId, expect, getCurrentState(), update);
        }
        return success;
    }

    public void addCompletedFactor(AuthType factorType) {
        if (factorType != null) {
            // EnumSet은 thread-safe하지 않으므로, 동시 접근 가능성이 있다면 Collections.synchronizedSet 등으로 감싸거나,
            // CopyOnWriteArraySet 사용 고려. 여기서는 completedMfaFactors가 final EnumSet.noneOf()로 초기화되므로,
            // add 시점에 스레드 안전성 확보 필요. 현재는 단일 스레드 처리를 가정.
            synchronized (this.completedMfaFactors) {
                this.completedMfaFactors.add(factorType);
            }
            this.lastActivityTimestamp = Instant.now();
            log.debug("FactorContext (ID: {}): Factor {} marked as completed.", mfaSessionId, factorType);
        }
    }

    public int incrementAttemptCount(@Nullable AuthType factorType) {
        if (factorType == null) {
            log.warn("FactorContext (ID: {}): Attempted to increment attempt count for a null factorType.", mfaSessionId);
            return 0; // 또는 예외
        }
        int newCount = factorAttemptCounts.compute(factorType, (key, val) -> (val == null) ? 1 : val + 1);
        this.lastActivityTimestamp = Instant.now();
        log.debug("FactorContext (ID: {}): Attempt count for {} incremented to {}.", mfaSessionId, factorType, newCount);
        return newCount;
    }

    public int getAttemptCount(@Nullable AuthType factorType) {
        if (factorType == null) return 0;
        return factorAttemptCounts.getOrDefault(factorType, 0);
    }

    public void recordAttempt(@Nullable AuthType factorType, boolean success, String detail) {
        this.mfaAttemptHistory.add(new MfaAttemptDetail(factorType, success, detail));
        this.lastActivityTimestamp = Instant.now();
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
        this.lastActivityTimestamp = Instant.now(); // 속성 변경도 활동으로 간주
    }

    @Getter
    public static class MfaAttemptDetail implements Serializable {
        private static final long serialVersionUID = 20250519_04L;
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




