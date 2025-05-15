package io.springsecurity.springsecurity6x.security.core.mfa.context;

import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
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

    private final Map<AuthType, AuthenticationProcessingOptions> factorSpecificOptions;

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

    public FactorContext(Authentication primaryAuthentication, Map<AuthType, AuthenticationProcessingOptions> factorSpecificOptionsMap) {
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

    // 이 메소드는 AuthenticationStepConfig에 저장된 _options를 가져오므로,
    // AuthenticationStepConfig에 저장 시 사용된 타입이 AuthenticationProcessingOptions 또는 그 하위 타입이어야 함.
    public AuthenticationProcessingOptions getCurrentFactorOptions() {
        if (this.currentProcessingFactor == null) {
            return null;
        }
        // MfaDslConfigurerImpl 에서 AuthenticationStepConfig의 "_options"에
        // AuthenticationProcessingOptions의 구체적인 하위타입 (예: OttOptions)을 저장했으므로,
        // 이 메소드가 그 값을 반환하도록 FactorContext가 해당 값을 어딘가에 가지고 있어야 함.
        // 가장 직접적인 방법은 AuthenticationStepConfig 자체를 FactorContext가 알거나,
        // currentProcessingFactor에 해당하는 옵션을 factorSpecificOptions 맵에서 가져오는 것.
        // MfaDslConfigurerImpl 에서 registeredFactorOptionsMap에 저장하는 것을 활용.
        return this.factorSpecificOptions.get(this.currentProcessingFactor);
    }

    public void setAllFactorSpecificOptions(Map<AuthType, AuthenticationProcessingOptions> factorOptionsMap) {
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

    @Getter
    public static class MfaAttemptDetail{
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




