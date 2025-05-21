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

    private static final long serialVersionUID = 20250522_01L;

    private final String mfaSessionId;
    private final AtomicReference<MfaState> currentMfaState;
    private final AtomicInteger version = new AtomicInteger(0);

    private final Authentication primaryAuthentication;
    private final String username;

    @Setter @Nullable private String flowTypeName;
    @Setter @Nullable private AuthType currentProcessingFactor;
    @Setter @Nullable private String currentStepId;
    @Setter @Nullable private AuthenticationProcessingOptions currentFactorOptions;
    @Setter private boolean mfaRequiredAsPerPolicy = false;

    private final List<AuthenticationStepConfig> completedFactors = new CopyOnWriteArrayList<>();
    private final Map<String, Integer> failedAttempts = new ConcurrentHashMap<>();
    private Instant lastActivityTimestamp;
//    private final Set<AuthType> completedMfaFactors = EnumSet.noneOf(AuthType.class);
    private final Map<String, Object> registeredMfaFactors = new ConcurrentHashMap<>();
    private final Map<AuthType, Integer> factorAttemptCounts = new ConcurrentHashMap<>();
    private final List<MfaAttemptDetail> mfaAttemptHistory = new CopyOnWriteArrayList<>();

    public FactorContext(String mfaSessionId, Authentication primaryAuthentication, MfaState initialState, @Nullable String flowTypeName) {
        Assert.hasText(mfaSessionId, "mfaSessionId cannot be empty");
        Assert.notNull(primaryAuthentication, "primaryAuthentication cannot be null");
        Assert.notNull(initialState, "initialState cannot be null");

        this.mfaSessionId = mfaSessionId;
        this.primaryAuthentication = primaryAuthentication;
        this.username = primaryAuthentication.getName();
        this.currentMfaState = new AtomicReference<>(initialState);
        this.flowTypeName = flowTypeName;
        this.lastActivityTimestamp = Instant.now();
        log.debug("FactorContext (ID: {}) created for user '{}' with initial state: {}. Flow type: {}",
                mfaSessionId, this.username, initialState, flowTypeName);
    }

    public MfaState getCurrentState() {
        return this.currentMfaState.get();
    }

    public boolean changeState(MfaState newState) {
        MfaState previousState = this.currentMfaState.getAndSet(newState);
        if (previousState != newState) {
            this.version.incrementAndGet();
            log.info("FactorContext (ID: {}) state changed from {} to {} for user '{}'. Version: {}",
                    mfaSessionId, previousState, newState, this.username, this.version.get());
            updateLastActivityTimestamp();
            return true;
        }
        return false;
    }

    public void addCompletedFactor(AuthenticationStepConfig completedFactor) {
        Assert.notNull(completedFactor, "completedFactor cannot be null");
        if (this.completedFactors.stream().noneMatch(step -> step.getStepId().equals(completedFactor.getStepId()))) {
            this.completedFactors.add(completedFactor);
            log.debug("FactorContext (ID: {}): Factor '{}' (StepId: {}) marked as completed for user {}. Total completed: {}",
                    mfaSessionId, completedFactor.getType(), completedFactor.getStepId(), this.username, this.completedFactors.size());
            updateLastActivityTimestamp();
        } else {
            log.debug("FactorContext (ID: {}): Factor '{}' (StepId: {}) already completed for user {}. Not adding again.",
                    mfaSessionId, completedFactor.getType(), completedFactor.getStepId(), this.username);
        }
    }


    public int getNumberOfCompletedFactors() {
        return this.completedFactors.size();
    }

    public int getLastCompletedFactorOrder() {
        if (completedFactors.isEmpty()) {
            return 0;
        }
        return completedFactors.stream()
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

    public int incrementFailedAttempts(String factorTypeOrStepId) {
        Assert.hasText(factorTypeOrStepId, "factorTypeOrStepId cannot be empty");
        int attempts = this.failedAttempts.compute(factorTypeOrStepId, (key, currentAttempts) -> (currentAttempts == null) ? 1 : currentAttempts + 1);
        log.debug("FactorContext (ID: {}): Failed attempt for factor/step '{}' incremented to {}. User: {}",
                mfaSessionId, factorTypeOrStepId, attempts, this.username);
        updateLastActivityTimestamp();
        return attempts;
    }

    public int getFailedAttempts(String factorTypeOrStepId) {
        return this.failedAttempts.getOrDefault(factorTypeOrStepId, 0);
    }

    public void resetFailedAttempts(String factorTypeOrStepId) {
        this.failedAttempts.remove(factorTypeOrStepId);
        log.debug("FactorContext (ID: {}): Failed attempts for factor/step '{}' reset. User: {}",
                mfaSessionId, factorTypeOrStepId, this.username);
        updateLastActivityTimestamp();
    }

    public void resetAllFailedAttempts() {
        this.failedAttempts.clear();
        log.debug("FactorContext (ID: {}): All failed attempts reset. User: {}", mfaSessionId, this.username);
        updateLastActivityTimestamp();
    }

    @Nullable
    public Object getAttribute(String key) {
        return this.registeredMfaFactors.get(key);
    }

    public void setAttribute(String key, @Nullable Object value) {
        Assert.hasText(key, "Attribute key cannot be empty or null.");
        if (value == null) {
            this.registeredMfaFactors.remove(key);
            log.debug("FactorContext (ID: {}): Attribute removed: Key='{}' for user {}", mfaSessionId, key, this.username);
        } else {
            this.registeredMfaFactors.put(key, value);
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

    public boolean isCompleted() {
        // MfaState에 MFA_FULLY_COMPLETED 또는 MFA_SUCCESS 와 같은 최종 완료 상태가 정의되어 있어야 함.
        // 현재 FactorContext에는 MfaState.MFA_COMPLETED 만 정의되어 있을 수 있으므로,
        // DefaultMfaPolicyProvider에서 모든 필수 팩터가 completedFactors에 있는지 확인하는 로직이 더 정확할 수 있음.
        return MfaState.MFA_FULLY_COMPLETED == this.currentMfaState.get();
    }

    public boolean isTerminal() {
        return this.currentMfaState.get().isTerminal();
    }

    public List<AuthType> getRegisteredMfaFactors() {
        Object registeredFactorsObj = registeredMfaFactors.get("registeredMfaFactors");
        if (registeredFactorsObj instanceof List) {
            try {
                @SuppressWarnings("unchecked")
                List<AuthType> factors = (List<AuthType>) registeredFactorsObj;
                return Collections.unmodifiableList(factors);
            } catch (ClassCastException e) {
                log.warn("Attribute 'registeredMfaFactors' is not a List of AuthType in FactorContext for user: {}", username);
            }
        }
        return Collections.emptyList();
    }

    public void setRegisteredMfaFactors(List<AuthType> registeredFactors) {
        setAttribute("registeredMfaFactors", new ArrayList<>(registeredFactors));
    }

    /**
     * 특정 인증 단계(stepId)가 완료되었는지 확인합니다.
     * @param stepId 확인할 스텝 ID
     * @return 완료되었으면 true, 아니면 false
     */
    public boolean isFactorCompleted(String stepId) {
        if (!StringUtils.hasText(stepId)) {
            return false;
        }
        return this.completedFactors.stream().anyMatch(step -> stepId.equals(step.getStepId()));
    }
}