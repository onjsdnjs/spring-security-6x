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

    private static final long serialVersionUID = 20250519_01L; // 날짜 기반으로 변경

    private final String mfaSessionId;
    private final AtomicReference<MfaState> currentMfaState; // 변경: 이전 currentState -> currentMfaState
    private final AtomicInteger version = new AtomicInteger(0);

    private final Authentication primaryAuthentication; // 1차 인증 성공 객체
    private final String username;

    // MFA 정책 및 진행 상태 관련 필드
    @Setter private boolean mfaRequiredAsPerPolicy = false; // MfaPolicyProvider가 평가한 MFA 필요 여부
    @Setter private EnumSet<AuthType> registeredMfaFactors = EnumSet.noneOf(AuthType.class); // 사용자에게 등록된 모든 MFA 수단
    @Setter @Nullable private AuthType preferredAutoAttemptFactor; // 현재 사용하지 않으나, 향후 자동 시도 로직 위해 유지
    @Setter @Nullable private AuthType currentProcessingFactor; // 현재 사용자가 선택했거나 시스템이 다음에 처리할 Factor
    private final Set<AuthType> completedMfaFactors = EnumSet.noneOf(AuthType.class); // 이번 MFA 세션에서 성공한 Factor 목록 (CopyOnWriteArraySet 또는 동기화된 Set 사용 고려)

    private final Map<AuthType, Integer> factorAttemptCounts = new ConcurrentHashMap<>();
    private Instant lastActivityTimestamp;
    private final List<MfaAttemptDetail> mfaAttemptHistory = new CopyOnWriteArrayList<>();
    private final Map<String, Object> attributes = new ConcurrentHashMap<>(); // 기타 확장 속성 (예: deviceId)

    // Factor별 옵션은 PlatformConfig -> AuthenticationFlowConfig -> AuthenticationStepConfig 에 저장되므로,
    // FactorContext에 직접 모든 옵션을 들고 있을 필요는 없을 수 있음.
    // 단, 현재 처리 중인 Factor의 옵션은 빠르게 접근하기 위해 currentProcessingFactorOptions 와 같이 가질 수 있음.
    // 여기서는 간결성을 위해 우선 제거. 필요시 추가.
    // private final Map<AuthType, AuthenticationProcessingOptions> factorSpecificOptions;

    public FactorContext(Authentication primaryAuthentication) {
        Assert.notNull(primaryAuthentication, "PrimaryAuthentication cannot be null when creating FactorContext.");
        this.mfaSessionId = UUID.randomUUID().toString();
        this.primaryAuthentication = primaryAuthentication;
        this.username = primaryAuthentication.getName();
        this.currentMfaState = new AtomicReference<>(MfaState.NONE); // 초기 상태는 NONE, 1차 인증 성공 핸들러에서 PRIMARY_AUTHENTICATION_COMPLETED로 설정
        this.lastActivityTimestamp = Instant.now();
        log.info("FactorContext created. Session ID: {}, Username: {}", mfaSessionId, this.username);
    }

    public MfaState getCurrentMfaState() {
        return currentMfaState.get();
    }

    public void setCurrentMfaState(MfaState newState) {
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
            log.warn("FactorContext (ID: {}) state compareAndSet FAILED. Expected: {}, Actual: {}, UpdateTo: {}", mfaSessionId, expect, getCurrentMfaState(), update);
        }
        return success;
    }

    public void addCompletedFactor(AuthType factorType) {
        if (factorType != null) {
            this.completedMfaFactors.add(factorType);
            this.lastActivityTimestamp = Instant.now();
            log.debug("FactorContext (ID: {}): Factor {} marked as completed.", mfaSessionId, factorType);
        }
    }

    public int incrementAttemptCount(@Nullable AuthType factorType) {
        if (factorType == null) {
            log.warn("FactorContext (ID: {}): Attempted to increment attempt count for a null factorType.", mfaSessionId);
            return 0;
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
    public Object getAttribute(String key) {
        return this.attributes.get(key);
    }

    public void setAttribute(String key, Object value) {
        this.attributes.put(key, value);
        log.debug("FactorContext (ID: {}): Attribute set: Key='{}', Value type='{}'", mfaSessionId, key, value != null ? value.getClass().getSimpleName() : "null");
    }

    @Getter
    public static class MfaAttemptDetail implements Serializable {
        private static final long serialVersionUID = 20250519_02L;
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




