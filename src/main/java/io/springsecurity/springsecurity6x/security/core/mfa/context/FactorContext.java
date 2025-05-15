package io.springsecurity.springsecurity6x.security.core.mfa.context;

import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.Getter;
import lombok.Setter; // 필요한 필드에만 선별적으로 사용하거나, 아래처럼 명시적 setter 사용
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

    private static final long serialVersionUID = 20240516_01L; // 날짜 기반으로 변경

    private final String mfaSessionId;
    private final AtomicReference<MfaState> currentState;
    private final AtomicInteger version = new AtomicInteger(0);

    // 1차 인증 정보 (불변으로 설정하거나, 초기화 후 변경되지 않도록 관리)
    private final Authentication primaryAuthentication;
    private final String username;

    // 각 Factor 타입별로 구성된 옵션들 (불변 컬렉션으로 관리)
    private final Map<AuthType, AuthenticationProcessingOptions> factorSpecificOptions;

    // --- MFA 정책 및 진행 상태 관련 필드 ---
    // 이 필드들은 Setter를 통해 외부(주로 MfaPolicyProvider 또는 관련 핸들러)에서 설정될 수 있어야 함
    @Setter
    private boolean mfaRequired = false;
    @Setter
    private Set<AuthType> registeredMfaFactors = EnumSet.noneOf(AuthType.class);
    @Setter
    @Nullable
    private AuthType preferredAutoAttemptFactor;

    @Setter
    private boolean autoAttemptFactorSucceeded = false;
    @Setter
    private boolean autoAttemptFactorSkippedOrFailed = false;

    // 현재 처리 중인 MFA Factor 타입 (Setter를 통해 상태 핸들러 등에서 설정)
    @Setter
    @Nullable
    private AuthType currentProcessingFactor;

    // Factor별 인증 시도 횟수 (내부에서만 변경)
    private final Map<AuthType, Integer> factorAttemptCounts = new ConcurrentHashMap<>();
    private Instant lastActivityTimestamp;

    // 현재 진행 중인 챌린지 관련 데이터 (예: Passkey 챌린지 옵션)
    private final Map<String, Object> currentChallengePayload = new ConcurrentHashMap<>();
    // MFA 시도 이력 (내부에서만 변경)
    private final List<MfaAttemptDetail> mfaAttemptHistory = new CopyOnWriteArrayList<>();
    // 기타 확장 속성
    private final Map<String, Object> attributes = new ConcurrentHashMap<>();

    /**
     * MFA 컨텍스트 생성자.
     * 일반적으로 1차 인증 성공 후 호출됩니다.
     *
     * @param primaryAuthentication        1차 인증 성공 결과 (null이 아니어야 함).
     * @param factorSpecificOptionsMap 각 Factor 타입별로 미리 구성된 옵션 맵 (null일 수 있음).
     * @param initialMfaState            MFA 흐름의 시작 상태 (일반적으로 PRIMARY_AUTHENTICATION_COMPLETED).
     */
    public FactorContext(Authentication primaryAuthentication,
                         @Nullable Map<AuthType, AuthenticationProcessingOptions> factorSpecificOptionsMap,
                         MfaState initialMfaState) {
        Assert.notNull(primaryAuthentication, "PrimaryAuthentication cannot be null when creating FactorContext.");
        Assert.notNull(initialMfaState, "InitialMfaState cannot be null.");

        this.mfaSessionId = UUID.randomUUID().toString();
        this.primaryAuthentication = primaryAuthentication;
        this.username = primaryAuthentication.getName();
        this.currentState = new AtomicReference<>(initialMfaState);

        this.factorSpecificOptions = (factorSpecificOptionsMap != null) ?
                Collections.unmodifiableMap(new HashMap<>(factorSpecificOptionsMap)) : // 불변 맵으로 저장
                Collections.emptyMap();
        this.lastActivityTimestamp = Instant.now();
        log.info("FactorContext created. Session ID: {}, Initial State: {}, Username: {}",
                mfaSessionId, this.currentState.get(), this.username);
    }

    /**
     * 1차 인증 정보와 기본 초기 상태(PRIMARY_AUTHENTICATION_COMPLETED)로 FactorContext를 생성하는 편의 생성자.
     *
     * @param primaryAuthentication 1차 인증 성공 결과 (null이 아니어야 함).
     */
    public FactorContext(Authentication primaryAuthentication) {
        this(primaryAuthentication, Collections.emptyMap(), MfaState.PRIMARY_AUTHENTICATION_COMPLETED);
    }

    /**
     * (테스트 또는 매우 특수한 시나리오용) 1차 인증 없이 특정 초기 상태와 사용자 이름으로 시작합니다.
     *
     * @param initialState             초기 MFA 상태.
     * @param username                 (선택적) 사용자 이름.
     * @param factorSpecificOptionsMap (선택적) Factor 옵션.
     */
    public FactorContext(MfaState initialState, @Nullable String username,
                         @Nullable Map<AuthType, AuthenticationProcessingOptions> factorSpecificOptionsMap) {
        Assert.notNull(initialState, "InitialMfaState cannot be null.");
        this.mfaSessionId = UUID.randomUUID().toString();
        this.primaryAuthentication = null; // 1차 인증 정보 없음
        this.username = username;
        this.currentState = new AtomicReference<>(initialState);
        this.factorSpecificOptions = (factorSpecificOptionsMap != null) ?
                Collections.unmodifiableMap(new HashMap<>(factorSpecificOptionsMap)) :
                Collections.emptyMap();
        this.lastActivityTimestamp = Instant.now();
        log.info("FactorContext created (manual init). Session ID: {}, Initial State: {}, Username: {}",
                mfaSessionId, this.currentState.get(), this.username);
    }


    public MfaState getCurrentState() {
        return currentState.get();
    }

    public int getVersion() {
        return version.get();
    }

    public void changeState(MfaState newState) {
        Assert.notNull(newState, "New MfaState cannot be null.");
        MfaState oldState = this.currentState.getAndSet(newState);
        if (oldState != newState) {
            this.version.incrementAndGet();
            this.lastActivityTimestamp = Instant.now();
            log.debug("FactorContext (ID: {}) state changed: {} -> {}", mfaSessionId, oldState, newState);
        }
    }

    public boolean compareAndSetState(MfaState expect, MfaState update) {
        Assert.notNull(expect, "Expected MfaState cannot be null.");
        Assert.notNull(update, "Update MfaState cannot be null.");
        boolean success = this.currentState.compareAndSet(expect, update);
        if (success) {
            this.version.incrementAndGet();
            this.lastActivityTimestamp = Instant.now();
            log.debug("FactorContext (ID: {}) state compareAndSet: {} -> {}. Success: {}", mfaSessionId, expect, update, true);
        } else {
            log.warn("FactorContext (ID: {}) state compareAndSet failed. Expected: {}, Actual: {}, UpdateTo: {}", mfaSessionId, expect, getCurrentState(), update);
        }
        return success;
    }

    @Nullable
    public AuthenticationProcessingOptions getOptionsForFactor(AuthType factorType) {
        return this.factorSpecificOptions.get(factorType);
    }

    @Nullable
    public AuthenticationProcessingOptions getCurrentFactorOptions() {
        if (this.currentProcessingFactor == null) {
            return null;
        }
        return getOptionsForFactor(this.currentProcessingFactor);
    }

    // setAllFactorSpecificOptions는 생성 시점에만 전달받도록 변경 (불변성 강화)

    public int incrementAttemptCount(@Nullable AuthType factorType) {
        if (factorType == null) {
            log.warn("FactorContext (ID: {}): Attempted to increment attempt count for a null factorType.", mfaSessionId);
            return 0; // 또는 예외 발생
        }
        int newCount = factorAttemptCounts.compute(factorType, (key, val) -> (val == null) ? 1 : val + 1);
        this.lastActivityTimestamp = Instant.now();
        log.debug("FactorContext (ID: {}): Attempt count incremented for {}: {}", mfaSessionId, factorType, newCount);
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
    public Object getChallengePayload(String key) {
        return this.currentChallengePayload.get(key);
    }

    public void setChallengePayload(String key, Object value) {
        this.currentChallengePayload.put(key, value);
        log.debug("FactorContext (ID: {}): Challenge payload set: Key='{}', Value type='{}'", mfaSessionId, key, value != null ? value.getClass().getSimpleName() : "null");
    }

    public void clearChallengePayload() {
        this.currentChallengePayload.clear();
        log.debug("FactorContext (ID: {}): Challenge payload cleared.", mfaSessionId);
    }

    @Nullable
    public Object getAttribute(String key) {
        return this.attributes.get(key);
    }

    public void setAttribute(String key, Object value) {
        this.attributes.put(key, value);
        log.debug("FactorContext (ID: {}): Attribute set: Key='{}', Value type='{}'", mfaSessionId, key, value != null ? value.getClass().getSimpleName() : "null");
    }

    @Getter
    public static class MfaAttemptDetail implements Serializable {
        private static final long serialVersionUID = 20240516_02L;
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

        @Override
        public String toString() {
            return "MfaAttemptDetail{" +
                    "factorType=" + factorType +
                    ", success=" + success +
                    ", timestamp=" + timestamp +
                    ", detail='" + detail + '\'' +
                    '}';
        }
    }

    @Override
    public String toString() {
        return "FactorContext{" +
                "mfaSessionId='" + mfaSessionId + '\'' +
                ", currentState=" + currentState.get() +
                ", version=" + version.get() +
                ", username='" + username + '\'' +
                ", mfaRequired=" + mfaRequired +
                ", currentProcessingFactor=" + currentProcessingFactor +
                ", registeredMfaFactors=" + registeredMfaFactors +
                ", preferredAutoAttemptFactor=" + preferredAutoAttemptFactor +
                ", autoAttemptFactorSucceeded=" + autoAttemptFactorSucceeded +
                ", autoAttemptFactorSkippedOrFailed=" + autoAttemptFactorSkippedOrFailed +
                ", lastActivityTimestamp=" + lastActivityTimestamp +
                '}';
    }
}




