package io.springsecurity.springsecurity6x.security.core.mfa.context;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

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

    private static final long serialVersionUID = 20250522_01L; // 날짜 기반으로 버전 업데이트

    private final String mfaSessionId;
    private final AtomicReference<MfaState> currentMfaState;
    private final AtomicInteger version = new AtomicInteger(0);

    private final Authentication primaryAuthentication;
    private final String username;

    @Setter @Nullable private String flowTypeName;
    @Setter @Nullable private String currentStepId;

    @Setter private boolean mfaRequiredAsPerPolicy = false;
    @Setter private EnumSet<AuthType> registeredMfaFactors = EnumSet.noneOf(AuthType.class);
    @Setter @Nullable private AuthType currentProcessingFactor;
    @Setter @Nullable private AuthenticationProcessingOptions currentFactorOptions; // 현재 Factor의 상세 옵션
    private final Set<AuthType> completedMfaFactors = EnumSet.noneOf(AuthType.class);

    // 자동 인증 시도 관련 필드는 필요에 따라 유지 또는 제거
    // @Setter @Nullable private AuthType preferredAutoAttemptFactor;
    // @Setter private boolean autoAttemptFactorSkippedOrFailed = false;
    // @Setter private boolean autoAttemptFactorSucceeded = false;

    private final Map<AuthType, Integer> factorAttemptCounts = new ConcurrentHashMap<>();
    private Instant lastActivityTimestamp;
    private final List<MfaAttemptDetail> mfaAttemptHistory = new CopyOnWriteArrayList<>();
    private final Map<String, Object> attributes = new ConcurrentHashMap<>();

    public FactorContext(Authentication primaryAuthentication, String flowTypeName) {
        Assert.notNull(primaryAuthentication, "PrimaryAuthentication cannot be null");
        Assert.isTrue(primaryAuthentication.isAuthenticated(), "PrimaryAuthentication must be authenticated");
        Assert.hasText(flowTypeName, "flowTypeName cannot be null or empty");

        this.mfaSessionId = UUID.randomUUID().toString();
        this.primaryAuthentication = primaryAuthentication;
        this.username = primaryAuthentication.getName();
        this.flowTypeName = StringUtils.hasText(flowTypeName) ? flowTypeName.toLowerCase() : "unknown_flow";
        // MFA 플로우의 경우 1차 인증 성공 후 바로 다음 단계를 평가하므로, PRIMARY_AUTHENTICATION_COMPLETED로 시작
        // 단일 인증 후 바로 MFA 없이 성공하는 경우는 이 FactorContext가 사용되지 않거나, 즉시 ALL_FACTORS_COMPLETED로 변경됨
        this.currentMfaState = new AtomicReference<>(MfaState.PRIMARY_AUTHENTICATION_COMPLETED);
        this.lastActivityTimestamp = Instant.now();
        log.info("FactorContext created for user '{}' in flow '{}'. Session ID: {}, Initial State: {}",
                this.username, this.flowTypeName, mfaSessionId, this.currentMfaState.get());
    }

    public MfaState getCurrentState() {
        return currentMfaState.get();
    }

    @Nullable
    public String getFlowTypeName() {
        return flowTypeName;
    }

    @Nullable
    public String getCurrentStepId() {
        return currentStepId;
    }

    @Nullable
    public AuthenticationProcessingOptions getCurrentFactorOptions() {
        return currentFactorOptions;
    }

    public void changeState(MfaState newState) {
        Assert.notNull(newState, "New MfaState cannot be null.");
        MfaState oldState = this.currentMfaState.getAndSet(newState);
        if (oldState != newState) {
            this.version.incrementAndGet();
            updateLastActivityTimestamp();
            log.info("FactorContext (ID: {}) state changed: {} -> {} for user {}", mfaSessionId, oldState, newState, this.username);
        }
    }

    public boolean compareAndSetState(MfaState expect, MfaState update) {
        Assert.notNull(expect, "Expected MfaState cannot be null.");
        Assert.notNull(update, "Update MfaState cannot be null.");
        boolean success = this.currentMfaState.compareAndSet(expect, update);
        if (success) {
            this.version.incrementAndGet();
            updateLastActivityTimestamp();
            log.info("FactorContext (ID: {}) state compareAndSet: {} -> {}. Success: {} for user {}", mfaSessionId, expect, update, true, this.username);
        } else {
            log.warn("FactorContext (ID: {}) state compareAndSet FAILED. Expected: {}, Actual: {}, UpdateTo: {} for user {}", mfaSessionId, expect, getCurrentState(), update, this.username);
        }
        return success;
    }

    public void addCompletedFactor(AuthType factorType) {
        if (factorType != null) {
            synchronized (this.completedMfaFactors) {
                this.completedMfaFactors.add(factorType);
            }
            updateLastActivityTimestamp();
            log.debug("FactorContext (ID: {}): Factor {} marked as completed for user {}.", mfaSessionId, factorType, this.username);
        }
    }

    /**
     * 마지막으로 완료된 인증 단계의 순서(order)를 반환합니다.
     * 완료된 단계가 없으면 0을 반환합니다.
     * @return 마지막 완료 단계의 order 값 또는 0
     */
    public int getLastCompletedFactorOrder() {
        if (completedMfaFactors.isEmpty()) {
            return 0;
        }
        // completedFactors가 order 순으로 정렬되어 있다고 가정하거나, 여기서 정렬 필요
        // 여기서는 마지막에 추가된 요소가 가장 높은 order를 가진다고 가정하지 않고,
        // completedFactors 리스트에서 가장 큰 order 값을 찾습니다.
        return completedMfaFactors.stream()
                .mapToInt(AuthenticationStepConfig::getOrder)
                .max()
                .orElse(0);
    }

    public int incrementAttemptCount(@Nullable AuthType factorType) {
        if (factorType == null) {
            log.warn("FactorContext (ID: {}): Attempted to increment attempt count for a null factorType for user {}.", mfaSessionId, this.username);
            return 0;
        }
        int newCount = factorAttemptCounts.compute(factorType, (key, val) -> (val == null) ? 1 : val + 1);
        updateLastActivityTimestamp();
        log.debug("FactorContext (ID: {}): Attempt count for {} incremented to {} for user {}.", mfaSessionId, factorType, newCount, this.username);
        return newCount;
    }

    public int getAttemptCount(@Nullable AuthType factorType) {
        if (factorType == null) return 0;
        return factorAttemptCounts.getOrDefault(factorType, 0);
    }

    public void recordAttempt(@Nullable AuthType factorType, boolean success, String detail) {
        this.mfaAttemptHistory.add(new MfaAttemptDetail(factorType, success, detail));
        updateLastActivityTimestamp();
        log.info("FactorContext (ID: {}): MFA attempt recorded: Factor={}, Success={}, Detail='{}' for user {}", mfaSessionId, factorType, success, detail, this.username);
    }

    @Nullable
    public Object getAttribute(String key) {
        return this.attributes.get(key);
    }

    public void setAttribute(String key, Object value) {
        Assert.hasText(key, "Attribute key cannot be empty or null.");
        if (value == null) {
            this.attributes.remove(key);
            log.debug("FactorContext (ID: {}): Attribute removed: Key='{}' for user {}", mfaSessionId, key, this.username);
        } else {
            this.attributes.put(key, value);
            log.debug("FactorContext (ID: {}): Attribute set: Key='{}', Value type='{}' for user {}", mfaSessionId, key, value.getClass().getSimpleName(), this.username);
        }
        updateLastActivityTimestamp();
    }
    public void updateLastActivityTimestamp() {
        this.lastActivityTimestamp = Instant.now();
        log.trace("FactorContext (ID: {}) lastActivityTimestamp updated to: {} for user {}", mfaSessionId, this.lastActivityTimestamp, this.username);
    }

    @Getter
    public static class MfaAttemptDetail implements Serializable {
        private static final long serialVersionUID = 20250522_02L;
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



