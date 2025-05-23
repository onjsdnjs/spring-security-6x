package io.springsecurity.springsecurity6x.security.core.mfa.context;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaState;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.io.Serializable;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

//@Getter
@Slf4j
@Setter
public class FactorContext implements FactorContextExtensions {

    private static final long serialVersionUID = 20250522_01L;

    private final String mfaSessionId;
    private final AtomicReference<MfaState> currentMfaState;
    private final AtomicInteger version = new AtomicInteger(0);

    private final Authentication primaryAuthentication;
    private final String username;
    private int retryCount = 0;
    private String lastError;
    private final long createdAt = System.currentTimeMillis();

    private String flowTypeName;
    private AuthType currentProcessingFactor;
    private String currentStepId;
    private AuthenticationProcessingOptions currentFactorOptions;
    private boolean mfaRequiredAsPerPolicy = false;

    private final List<AuthenticationStepConfig> completedFactors = new CopyOnWriteArrayList<>();
    private final Map<String, Integer> failedAttempts = new ConcurrentHashMap<>();
    private Instant lastActivityTimestamp;
//    private final Set<AuthType> completedMfaFactors = EnumSet.noneOf(AuthType.class);
    private final Map<String, Object> registeredMfaFactors = new ConcurrentHashMap<>();
    private final Map<AuthType, Integer> factorAttemptCounts = new ConcurrentHashMap<>();
    private final List<MfaAttemptDetail> mfaAttemptHistory = new CopyOnWriteArrayList<>();
    // 기타 속성 저장용 (재시도 횟수, 타임스탬프 등)
    private final Map<String, Object> attributes = new ConcurrentHashMap<>();

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


    public void changeState(MfaState newState) {
        MfaState previousState = this.currentMfaState.getAndSet(newState);
        if (previousState != newState) {
            this.version.incrementAndGet();
            log.info("FactorContext (ID: {}) state changed from {} to {} for user '{}'. Version: {}",
                    mfaSessionId, previousState, newState, this.username, this.version.get());
            updateLastActivityTimestamp();
        }
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

    /**
     * 마지막으로 완료된 인증 단계의 순서(order)를 반환합니다.
     * completedFactors가 List<AuthenticationStepConfig>이므로 정상 동작합니다.
     */
    public int getLastCompletedFactorOrder() {
        if (completedFactors.isEmpty()) {
            log.debug("FactorContext for user '{}': No completed factors, returning order 0.", username);
            return 0;
        }
        int maxOrder = completedFactors.stream()
                .mapToInt(AuthenticationStepConfig::getOrder) // AuthenticationStepConfig 객체에서 order를 가져옴
                .max()
                .orElse(0);
        log.debug("FactorContext for user '{}': Last completed factor order is {}.", username, maxOrder);
        return maxOrder;
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

    public void setAttribute(String name, Object value) {
        this.attributes.put(name, value);
        this.version.incrementAndGet();
    }

    @Nullable
    public Object getAttribute(String name) {
        return this.attributes.get(name);
    }

    public void removeAttribute(String name) {
        this.attributes.remove(name);
        this.version.incrementAndGet();
    }

    public boolean isFullyAuthenticated() {
        // 이 메소드는 DefaultMfaPolicyProvider.checkAllFactorsCompleted의 결과에 따라 상태가 변경된 것을 확인하는 용도.
        // 단순히 MFA_FULLY_COMPLETED 상태인지 확인.
        return MfaState.MFA_FULLY_COMPLETED == this.currentMfaState.get();
    }

    public void setRegisteredMfaFactors(String key, @Nullable Object value) {
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

    @Override
    public int getRetryCount() {
        return 0;
    }

    @Override
    public Set<AuthType> getAvailableFactors() {
        return Set.of();
    }

    @Override
    public Set<AuthType> getCompletedFactors() {
        return Set.of();
    }

    @Override
    public String getLastError() {
        return "";
    }

    @Override
    public long getCreatedAt() {
        return 0;
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
        // 현재 FactorContext 에는 MfaState.MFA_COMPLETED 만 정의되어 있을 수 있으므로,
        // DefaultMfaPolicyProvider 에서 모든 필수 팩터가 completedFactors에 있는지 확인하는 로직이 더 정확할 수 있음.
        return MfaState.MFA_FULLY_COMPLETED == this.currentMfaState.get();
    }

    public boolean isTerminal() {
        return this.currentMfaState.get().isTerminal();
    }

    /**
     * 현재 MFA 플로우 설정에 정의된 인증 단계 중, 사용자에게 등록되어 있고 아직 완료되지 않은 다음 단계를 반환합니다.
     * MfaPolicyProvider 에서 이 메소드를 사용하여 다음 진행할 단계를 결정할 수 있습니다.
     *
     * @param flowConfig 현재 MFA 플로우 설정
     * @param userRegisteredFactors 사용자가 실제로 등록한 MFA 요소 타입 목록 (예: userRepository 에서 조회)
     * @return 다음에 진행할 AuthenticationStepConfig, 없으면 null
     */
    @Nullable
    public AuthenticationStepConfig getNextStepToProcess(AuthenticationFlowConfig flowConfig, List<AuthType> userRegisteredFactors) {
        if (flowConfig == null || CollectionUtils.isEmpty(flowConfig.getStepConfigs())) {
            return null;
        }
        return flowConfig.getStepConfigs().stream()
                .filter(step -> userRegisteredFactors.contains(step.getType())) // 사용자가 등록한 타입의 단계만
                .filter(step -> !isFactorCompleted(step.getStepId())) // 아직 완료되지 않은 단계
                .findFirst()
                .orElse(null);
    }

    /**
     * 사용자가 등록한 MFA 요소 목록을 attributes 맵에서 가져옵니다.
     * 이 목록은 MfaPolicyProvider 등에 의해 "registeredMfaFactors" 키로 attributes에 저장되어야 합니다.
     */
    public List<AuthType> getRegisteredMfaFactors() {
        Object registeredFactorsObj = attributes.get("registeredMfaFactors");
        if (registeredFactorsObj instanceof List) {
            try {
                List<AuthType> factors = (List<AuthType>) registeredFactorsObj;
                return Collections.unmodifiableList(factors);
            } catch (ClassCastException e) {
                log.warn("Attribute 'registeredMfaFactors' is not a List of AuthType in FactorContext for user: {}. Returning empty list.", username, e);
            }
        }
        if (registeredFactorsObj != null) { // List가 아닌 다른 타입으로 저장된 경우 경고
            log.warn("Attribute 'registeredMfaFactors' in FactorContext for user {} is not a List (actual type: {}). Returning empty list.",
                    username, registeredFactorsObj.getClass().getName());
        }
        return Collections.emptyList();
    }

    /**
     * 지정된 MFA 플로우 설정 내에서 사용자가 등록한 MFA 요소(AuthType)들의 목록을 반환합니다.
     * 이 목록은 사용자가 실제로 사용할 수 있는 MFA 옵션을 나타냅니다.
     *
     * @param mfaFlowConfig 현재 MFA 플로우 설정
     * @return 해당 플로우에서 사용 가능한 (사용자가 등록한) AuthType 목록
     */
    public List<AuthType> getRegisteredMfaFactors(AuthenticationFlowConfig mfaFlowConfig) {
        // 이 로직은 MfaPolicyProvider의 getRegisteredMfaFactorsForUser(username)을 호출하고,
        // 그 결과를 mfaFlowConfig의 step 들과 비교하여 필터링해야 합니다.
        // 지금은 FactorContext가 직접 MfaPolicyProvider를 알 수 없으므로,
        // 이 FactorContext를 사용하는 측(예: MfaPolicyProvider)에서 이 정보를 채워주거나,
        // 또는 attributes 맵에 "userRegisteredFactorsInThisFlow"와 같이 저장해야 합니다.
        // 여기서는 간단하게 flowConfig에 있는 모든 AuthType을 반환한다고 가정하지만, 실제로는 필터링 필요.
        // 예를 들어, MfaPolicyProvider가 FactorContext 생성 시 또는 특정 시점에 이 정보를 attributes에 넣어줄 수 있습니다.
        Object factorsFromAttribute = getAttribute("userRegisteredFactorsInThisFlow");
        if (factorsFromAttribute instanceof List) {
            try {
                List<AuthType> factors = (List<AuthType>) factorsFromAttribute;
                return Collections.unmodifiableList(factors);
            } catch (ClassCastException e) {
                log.warn("Attribute 'userRegisteredFactorsInThisFlow' is not a List of AuthType in FactorContext for user: {}", username);
            }
        }

        // Fallback: 만약 attribute에 없다면, flow config의 모든 step type을 반환 (실제로는 필터링된 목록이어야 함)
        log.warn("FactorContext for user '{}': 'userRegisteredFactorsInThisFlow' attribute not found. " +
                        "Falling back to all AuthTypes defined in the current MFA flow '{}'. " +
                        "This might not accurately reflect user's registered factors for this specific flow.",
                username, flowTypeName);
        if (mfaFlowConfig != null && mfaFlowConfig.getStepConfigs() != null) {
            return mfaFlowConfig.getStepConfigs().stream()
                    .map(AuthenticationStepConfig::getType)
                    .map(AuthType::valueOf)
                    .distinct()
                    .collect(Collectors.toList());
        }
        return Collections.emptyList();
    }


    /**
     * 사용자가 등록한 MFA 요소 목록을 attributes 맵에 "registeredMfaFactors" 키로 저장합니다.
     * MfaPolicyProvider 등에서 호출합니다.
     * @param registeredFactors 사용자가 등록한 AuthType 목록
     */
    public void setRegisteredMfaFactors(List<AuthType> registeredFactors) {
        if (registeredFactors == null) {
            setAttribute("registeredMfaFactors", new ArrayList<>());
            log.debug("FactorContext for user '{}': Set registered MFA factors to an empty list (input was null).", username);
        } else {
            setAttribute("registeredMfaFactors", new ArrayList<>(registeredFactors)); // 방어적 복사
            log.debug("FactorContext for user '{}': Set registered MFA factors: {}", username, registeredFactors);
        }
    }

    /**
     * 현재 처리 중인 팩터 관련 상태(currentProcessingFactor, currentStepId, currentFactorOptions)를 초기화합니다.
     * 주로 다음 팩터 선택 화면으로 이동하기 전에 호출됩니다.
     */
    public void clearCurrentFactorProcessingState() {
        log.debug("FactorContext for user '{}', flow '{}': Clearing current factor processing state.", username, flowTypeName);
        this.currentProcessingFactor = null;
        this.currentStepId = null;
        this.currentFactorOptions = null;
        this.version.incrementAndGet();
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
        // completedFactors가 List<AuthenticationStepConfig>이므로, stepId로 비교
        return this.completedFactors.stream().anyMatch(cf -> stepId.equals(cf.getStepId()));
    }

    // 내부 클래스: 완료된 MFA 요소 정보
    @Getter
    public static class CompletedFactorInfo implements Serializable {
        private static final long serialVersionUID = 1L;
        private final AuthType factorType;
        private final String stepId; // 어떤 AuthenticationStepConfig에 해당하는지 식별
        private final Instant completionTime;
        @Nullable private final transient AuthenticationProcessingOptions factorOptions; // 완료 시점의 옵션 (직렬화 제외 고려)

        public CompletedFactorInfo(AuthType factorType, String stepId, Instant completionTime, @Nullable AuthenticationProcessingOptions factorOptions) {
            this.factorType = factorType;
            this.stepId = stepId;
            this.completionTime = completionTime;
            this.factorOptions = factorOptions;
        }

        @Override
        public String toString() {
            return "CompletedFactorInfo{" +
                    "factorType=" + factorType +
                    ", stepId='" + stepId + '\'' +
                    ", completionTime=" + completionTime +
                    '}';
        }
    }
}