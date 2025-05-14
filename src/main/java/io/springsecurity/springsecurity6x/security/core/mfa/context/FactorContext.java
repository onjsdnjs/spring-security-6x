package io.springsecurity.springsecurity6x.security.core.mfa.context;

import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.Authentication;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID; // 세션 ID 생성을 위해 추가
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

@Getter
@Setter
public class FactorContext implements Serializable {

    private static final long serialVersionUID = 20240514L; // 예시 Serializable UID

    private final String mfaSessionId;
    private final AtomicReference<MfaState> currentState;
    private final AtomicInteger version = new AtomicInteger(0);

    private Authentication primaryAuthentication; // 1차 인증 성공 객체
    private String username; // 1차 인증된 사용자 이름

    // 사용자의 MFA 설정 (MfaPolicyProvider를 통해 로드될 수 있음)
    private Set<AuthType> registeredMfaFactors; // 사용자가 등록/활성화한 MFA 수단
    private AuthType preferredAutoAttemptFactor; // 정책에 의해 결정된 자동 시도 Factor
    private boolean autoAttemptFactorSucceeded = false; // 자동 시도 Factor 성공 여부
    private boolean autoAttemptFactorSkippedOrFailed = false; // 자동 시도 Factor를 건너뛰었거나 실패했는지 여부

    // 현재 진행 중인 Factor 처리 정보
    private AuthType currentProcessingFactor; // 현재 사용자가 선택했거나 시스템이 처리 중인 Factor
    private final Map<AuthType, Integer> factorAttemptCounts = new ConcurrentHashMap<>(); // Factor별 시도 횟수
    private Instant lastActivityTimestamp; // 마지막 사용자/시스템 활동 시간 (세션 타임아웃용)

    // 현재 Factor 챌린지 데이터
    private final Map<String, Object> currentChallengePayload = new ConcurrentHashMap<>();

    // MFA 시도 이력
    private final List<MfaAttemptDetail> mfaAttemptHistory = new CopyOnWriteArrayList<>();

    // 기타 부가 정보 저장용
    private final Map<String, Object> attributes = new ConcurrentHashMap<>();

    public FactorContext(Authentication primaryAuthentication) {
        this.mfaSessionId = UUID.randomUUID().toString();
        this.primaryAuthentication = primaryAuthentication;
        if (primaryAuthentication != null) {
            this.username = primaryAuthentication.getName();
            this.currentState = new AtomicReference<>(MfaState.PRIMARY_AUTHENTICATION_COMPLETED);
        } else {
            // 1차 인증 정보가 없는 초기 상태 (예: 세션에 처음 FactorContext 생성 시)
            // 이 경우 username은 나중에 설정되어야 함
            this.username = null;
            this.currentState = new AtomicReference<>(MfaState.AWAITING_MFA_FACTOR_SELECTION); // 또는 다른 적절한 초기 상태
        }
        this.lastActivityTimestamp = Instant.now();
    }

    public MfaState getCurrentState() {
        return currentState.get();
    }

    public int getVersion() {
        return version.get();
    }

    public void changeState(MfaState newState) {
        this.currentState.set(newState);
        this.version.incrementAndGet();
        this.lastActivityTimestamp = Instant.now();
    }

    public boolean compareAndSetState(MfaState expect, MfaState update) {
        boolean success = this.currentState.compareAndSet(expect, update);
        if (success) {
            this.version.incrementAndGet();
            this.lastActivityTimestamp = Instant.now();
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
        this.currentProcessingFactor = currentProcessingFactor;
        this.lastActivityTimestamp = Instant.now();
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


    /**
     * MFA 시도 이력 저장을 위한 내부 클래스
     */
    public static class MfaAttemptDetail implements Serializable {
        private static final long serialVersionUID = 2024051401L;
        public final AuthType factorType;
        public final boolean success;
        public final Instant timestamp;
        public final String detail;

        public MfaAttemptDetail(AuthType factorType, boolean success, String detail) {
            this.factorType = factorType;
            this.success = success;
            this.timestamp = Instant.now();
            this.detail = detail;
        }
    }
}


