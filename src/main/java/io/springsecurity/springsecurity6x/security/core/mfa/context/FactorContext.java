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

    private final String mfaSessionId;
    private final AtomicReference<MfaState> currentState;
    private final AtomicInteger version = new AtomicInteger(0);

    private Authentication primaryAuthentication;
    private String username;

    // MFA 흐름에 등록된 각 Factor의 구체적인 설정 (MFA DSL에서 주입되어야 함)
    private Map<AuthType, FactorAuthenticationOptions> factorSpecificOptions = new ConcurrentHashMap<>();

    private Set<AuthType> registeredMfaFactors;
    private AuthType preferredAutoAttemptFactor;
    private boolean autoAttemptFactorSucceeded = false;
    private boolean autoAttemptFactorSkippedOrFailed = false;

    private AuthType currentProcessingFactor; // 현재 처리 중인 Factor
    private final Map<AuthType, Integer> factorAttemptCounts = new ConcurrentHashMap<>();
    private Instant lastActivityTimestamp;

    private final Map<String, Object> currentChallengePayload = new ConcurrentHashMap<>();
    private final List<MfaAttemptDetail> mfaAttemptHistory = new CopyOnWriteArrayList<>();
    private final Map<String, Object> attributes = new ConcurrentHashMap<>();

    /**
     * FactorContext 생성자.
     *
     * @param primaryAuthentication 1차 인증 성공 객체 (null일 수 있음)
     * @param factorSpecificOptionsMap MFA 흐름에 설정된 각 Factor의 옵션 맵 (null일 수 있음)
     */
    public FactorContext(Authentication primaryAuthentication, Map<AuthType, FactorAuthenticationOptions> factorSpecificOptionsMap) {
        this.mfaSessionId = UUID.randomUUID().toString();
        this.primaryAuthentication = primaryAuthentication;

        if (primaryAuthentication != null) {
            this.username = primaryAuthentication.getName();
            // 1차 인증 성공 시, 다음 상태는 일반적으로 MFA Factor 선택 또는 첫 번째 Factor 챌린지 시작
            this.currentState = new AtomicReference<>(MfaState.PRIMARY_AUTHENTICATION_COMPLETED); // 또는 AWAITING_MFA_FACTOR_SELECTION
        } else {
            this.username = null;
            // 1차 인증 없이 바로 MFA 흐름이 시작되는 경우 (예: 특정 리소스 접근 시 추가 인증)
            this.currentState = new AtomicReference<>(MfaState.AWAITING_MFA_FACTOR_SELECTION); // 또는 적절한 초기 상태
        }

        if (factorSpecificOptionsMap != null) {
            this.factorSpecificOptions.putAll(factorSpecificOptionsMap);
        }

        this.lastActivityTimestamp = Instant.now();
        log.debug("[FactorContext] Created new FactorContext. Session ID: {}, Initial State: {}, Username: {}",
                this.mfaSessionId, this.currentState.get(), this.username);
    }

    // 기존 생성자와의 호환성을 위해 남겨두거나, 위 생성자로 통합
    public FactorContext(Authentication primaryAuthentication) {
        this(primaryAuthentication, Collections.emptyMap()); // factorSpecificOptions를 빈 맵으로 초기화
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

    public void setPrimaryAuthentication(Authentication primaryAuthentication) {
        this.primaryAuthentication = primaryAuthentication;
        if (primaryAuthentication != null) {
            this.username = primaryAuthentication.getName();
        }
    }

    public void setCurrentProcessingFactor(AuthType currentProcessingFactor) {
        log.debug("[FactorContext] Setting current processing factor to: {}. Session ID: {}", currentProcessingFactor, this.mfaSessionId);
        this.currentProcessingFactor = currentProcessingFactor;
        this.lastActivityTimestamp = Instant.now();
    }

    /**
     * 현재 처리 중인 인증 요소(Factor)에 대한 설정 객체(FactorAuthenticationOptions)를 반환합니다.
     * 이 메소드가 올바르게 동작하려면, FactorContext 내의 'currentProcessingFactor' 필드가
     * 현재 인증 단계를 정확히 가리키고 있어야 하며, 'factorSpecificOptions' 맵에는
     * 해당 Factor에 대한 설정 정보가 미리 로드되어 있어야 합니다.
     *
     * @return 현재 Factor에 대한 FactorAuthenticationOptions 객체. 해당 Factor나 옵션이 없으면 null을 반환합니다.
     */
    public FactorAuthenticationOptions getCurrentFactorOptions() {
        if (this.currentProcessingFactor != null && this.factorSpecificOptions != null) {
            FactorAuthenticationOptions options = this.factorSpecificOptions.get(this.currentProcessingFactor);
            if (options == null) {
                log.warn("[FactorContext] No specific options found for currentProcessingFactor: {} in factorSpecificOptions map. Session ID: {}",
                        this.currentProcessingFactor, this.mfaSessionId);
            }
            return options;
        }
        log.warn("[FactorContext] Attempted to get current factor options, but currentProcessingFactor ({}) or factorSpecificOptions map is null. Session ID: {}",
                this.currentProcessingFactor, this.mfaSessionId);
        return null;
    }

    /**
     * 특정 Factor에 대한 옵션을 설정합니다. MfaDslConfigurer 등에서 사용될 수 있습니다.
     * @param factorType 설정할 Factor의 AuthType
     * @param options 해당 Factor의 FactorAuthenticationOptions
     */
    public void setFactorOptions(AuthType factorType, FactorAuthenticationOptions options) {
        if (factorType != null && options != null) {
            this.factorSpecificOptions.put(factorType, options);
            log.debug("[FactorContext] Set options for factor {}. Session ID: {}", factorType, this.mfaSessionId);
        }
    }


    public int incrementAttemptCountForCurrentFactor() {
        if (this.currentProcessingFactor == null) return 0;
        int newCount = factorAttemptCounts.merge(this.currentProcessingFactor, 1, Integer::sum);
        this.lastActivityTimestamp = Instant.now();
        return newCount;
    }

    public void resetAttemptCountForFactor(AuthType factorType) {
        factorAttemptCounts.remove(factorType);
    }

    public int getAttemptCountForFactor(AuthType factorType) {
        return factorAttemptCounts.getOrDefault(factorType, 0);
    }

    public void updateLastActivityTimestamp() {
        this.lastActivityTimestamp = Instant.now();
    }

    public void addChallengePayload(String key, Object value) {
        this.currentChallengePayload.put(key, value);
    }

    public Object getChallengePayload(String key) {
        return this.currentChallengePayload.get(key);
    }

    public void clearChallengePayload() {
        this.currentChallengePayload.clear();
    }

    public void recordAttempt(AuthType factorType, boolean success, String detail) {
        this.mfaAttemptHistory.add(new MfaAttemptDetail(factorType, success, detail));
        this.lastActivityTimestamp = Instant.now();
    }

    public void setAttribute(String name, Object value) {
        this.attributes.put(name, value);
    }

    public Object getAttribute(String name) {
        return this.attributes.get(name);
    }

    public <T> T getAttributeOrDefault(String key, T defaultValue) {
        Object value = attributes.get(key);
        if (defaultValue != null && defaultValue.getClass().isInstance(value)) {
            return (T) value;
        }
        if (value == null && defaultValue != null) {
            return defaultValue;
        }
        if (value != null && defaultValue == null) { // 값은 있지만 기본값이 null인 경우 (타입 체크 없이 반환)
            try {
                return (T) value;
            } catch (ClassCastException e) {
                log.warn("[FactorContext] Attribute '{}' is of type {} but expected type {}. Returning default. Session ID: {}",
                        key, value.getClass().getName(), defaultValue != null ? defaultValue.getClass().getName() : "unknown", this.mfaSessionId, e);
                return defaultValue;
            }
        }
        return defaultValue;
    }


    @Getter
    public static class MfaAttemptDetail {
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


