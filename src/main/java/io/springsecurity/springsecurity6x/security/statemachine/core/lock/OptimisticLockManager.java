// Path: onjsdnjs/spring-security-6x/spring-security-6x-IdentityPlatform_0.0.5.optimizer/src/main/java/io/springsecurity/springsecurity6x/security/statemachine/core/lock/OptimisticLockManager.java
package io.springsecurity.springsecurity6x.security.statemachine.core.lock;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.Serializable; // Serializable 추가
import java.time.Instant; // 추가
import java.util.ArrayList; // 추가
import java.util.Collections; // 추가
import java.util.List; // 추가
import java.util.Map;
import java.util.Objects; // 추가
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@Component
public class OptimisticLockManager {

    private final Map<String, VersionInfo> versionMap = new ConcurrentHashMap<>();
    private final Map<String, CachedState> stateCache = new ConcurrentHashMap<>();
    private final Map<String, CachedContext> contextCache = new ConcurrentHashMap<>(); // 추가

    private final AtomicLong totalConflicts = new AtomicLong(0);
    private final AtomicLong totalChecks = new AtomicLong(0);

    // ... (기존 checkVersion, updateVersion, incrementVersion 메서드 유지) ...
    public boolean checkVersion(String sessionId, int expectedVersion) {
        totalChecks.incrementAndGet();

        VersionInfo versionInfo = versionMap.get(sessionId);
        if (versionInfo == null) {
            versionMap.put(sessionId, new VersionInfo(expectedVersion));
            return true;
        }

        boolean valid = versionInfo.version.get() == expectedVersion;

        if (!valid) {
            totalConflicts.incrementAndGet();
            versionInfo.conflictCount.incrementAndGet();
            log.warn("Version conflict for session: {}. Expected: {}, Actual: {}",
                    sessionId, expectedVersion, versionInfo.version.get());
        }
        return valid;
    }

    public void updateVersion(String sessionId, int newVersion) {
        versionMap.compute(sessionId, (key, info) -> {
            if (info == null) {
                return new VersionInfo(newVersion);
            }
            info.version.set(newVersion);
            info.lastUpdated = System.currentTimeMillis();
            return info;
        });
        log.debug("Version updated for session: {} to {}", sessionId, newVersion);
    }

    public int incrementVersion(String sessionId) {
        VersionInfo info = versionMap.compute(sessionId, (key, existing) -> {
            if (existing == null) {
                return new VersionInfo(1);
            }
            existing.version.incrementAndGet();
            existing.lastUpdated = System.currentTimeMillis();
            return existing;
        });
        return info.version.get();
    }

    public MfaState getCachedState(String sessionId) {
        CachedState cached = stateCache.get(sessionId);
        if (cached != null && !cached.isExpired()) {
            cached.hitCount.incrementAndGet();
            return cached.state;
        }
        return null;
    }

    public void updateCachedState(String sessionId, MfaState state) {
        stateCache.put(sessionId, new CachedState(state));
    }

    public FactorContext getCachedContext(String sessionId) {
        CachedContext cached = contextCache.get(sessionId);
        if (cached != null && !cached.isExpired()) {
            cached.hitCount.incrementAndGet();
            // 캐시된 컨텍스트의 복사본 반환하여 외부 수정 방지
            return CachedContext.createContextCopy(cached.context);
        }
        return null;
    }

    public void updateCachedContext(String sessionId, FactorContext context) {
        if (context != null) {
            contextCache.put(sessionId, new CachedContext(context));
        } else {
            contextCache.remove(sessionId); // context가 null이면 캐시에서 제거
        }
    }

    public void invalidateCache(String sessionId) { // 이름 변경 및 contextCache 제거 추가
        stateCache.remove(sessionId);
        contextCache.remove(sessionId); // 추가
        log.debug("State and Context cache invalidated for session: {}", sessionId);
    }

    public void invalidateContextCache(String sessionId) { // 명시적인 컨텍스트 캐시 무효화
        contextCache.remove(sessionId);
        log.debug("Context cache explicitly invalidated for session: {}", sessionId);
    }


    public void clearCache(String sessionId) {
        versionMap.remove(sessionId);
        stateCache.remove(sessionId);
        contextCache.remove(sessionId); // 추가
        log.debug("All caches (version, state, context) cleared for session: {}", sessionId);
    }

    public ConflictResolution resolveConflict(String sessionId, int clientVersion, int serverVersion) {
        // ... (기존 로직 유지) ...
        if (clientVersion == serverVersion) {
            return ConflictResolution.NO_CONFLICT;
        }

        VersionInfo info = versionMap.get(sessionId);
        if (info == null) {
            return ConflictResolution.ACCEPT_CLIENT;
        }

        int conflicts = info.conflictCount.get();
        if (conflicts > 10) {
            return ConflictResolution.FORCE_REFRESH;
        } else if (serverVersion - clientVersion > 5) {
            return ConflictResolution.USE_SERVER;
        } else {
            return ConflictResolution.MERGE;
        }
    }

    public OptimisticLockStatistics getStatistics() {
        // ... (기존 로직 유지) ...
        long checks = totalChecks.get();
        long conflicts = totalConflicts.get();

        return new OptimisticLockStatistics(
                checks,
                conflicts,
                checks > 0 ? (double) conflicts / checks : 0,
                versionMap.size(),
                stateCache.size(),
                contextCache.size() // contextCache 크기 추가
        );
    }


    public void cleanup(long maxAgeMillis) {
        long cutoff = System.currentTimeMillis() - maxAgeMillis;
        int versionMapSizeBefore = versionMap.size();
        int stateCacheSizeBefore = stateCache.size();
        int contextCacheSizeBefore = contextCache.size(); // 추가

        versionMap.entrySet().removeIf(entry -> entry.getValue().lastUpdated < cutoff);
        stateCache.entrySet().removeIf(entry -> entry.getValue().isExpired(maxAgeMillis)); // 만료 기준 전달
        contextCache.entrySet().removeIf(entry -> entry.getValue().isExpired(maxAgeMillis)); // 추가 및 만료 기준 전달

        log.info("Cache cleanup completed. Removed versions: {}, states: {}, contexts: {}. Max age: {}ms",
                versionMapSizeBefore - versionMap.size(),
                stateCacheSizeBefore - stateCache.size(),
                contextCacheSizeBefore - contextCache.size(), // 추가
                maxAgeMillis);
    }

    private static class VersionInfo {
        final AtomicInteger version;
        final AtomicInteger conflictCount = new AtomicInteger(0);
        volatile long lastUpdated;

        VersionInfo(int initialVersion) {
            this.version = new AtomicInteger(initialVersion);
            this.lastUpdated = System.currentTimeMillis();
        }
    }

    private static class CachedState {
        final MfaState state;
        final long cachedAt;
        final AtomicInteger hitCount = new AtomicInteger(0);

        CachedState(MfaState state) {
            this.state = state;
            this.cachedAt = System.currentTimeMillis();
        }

        boolean isExpired(long maxAgeMillis) { // 만료 기준 파라미터 추가
            return System.currentTimeMillis() - cachedAt > maxAgeMillis;
        }
    }

    // OptimisticLockStatistics 내부 클래스에 contextCacheCount 필드 추가
    public static class OptimisticLockStatistics {
        private final long totalChecks;
        private final long totalConflicts;
        private final double conflictRate;
        private final int activeVersions;
        private final int cachedStates;
        private final int cachedContexts; // 추가

        public OptimisticLockStatistics(long totalChecks, long totalConflicts,
                                        double conflictRate, int activeVersions,
                                        int cachedStates, int cachedContexts) { // 생성자 수정
            this.totalChecks = totalChecks;
            this.totalConflicts = totalConflicts;
            this.conflictRate = conflictRate;
            this.activeVersions = activeVersions;
            this.cachedStates = cachedStates;
            this.cachedContexts = cachedContexts; // 할당
        }

        public long getTotalChecks() { return totalChecks; }
        public long getTotalConflicts() { return totalConflicts; }
        public double getConflictRate() { return conflictRate; }
        public int getActiveVersions() { return activeVersions; }
        public int getCachedStates() { return cachedStates; }
        public int getCachedContexts() { return cachedContexts; } // Getter 추가

        @Override
        public String toString() {
            return String.format(
                    "OptimisticLockStats[checks=%d, conflicts=%d, rate=%.2f%%, versions=%d, cachedStates=%d, cachedContexts=%d]", // 출력 수정
                    totalChecks, totalConflicts, conflictRate * 100, activeVersions, cachedStates, cachedContexts
            );
        }
    }


    private static class CachedContext implements Serializable { // Serializable 구현
        private static final long serialVersionUID = 1L; // serialVersionUID 추가

        final FactorContext context;
        final long cachedAt;
        final AtomicInteger hitCount = new AtomicInteger(0);

        CachedContext(FactorContext context) {
            this.context = createContextCopy(context);
            this.cachedAt = System.currentTimeMillis();
        }

        boolean isExpired(long maxAgeMillis) { // 만료 기준 파라미터 추가
            return System.currentTimeMillis() - cachedAt > maxAgeMillis;
        }

        // FactorContext 복사본 생성 (깊은 복사 고려)
        static FactorContext createContextCopy(FactorContext original) {
            if (original == null) return null;
            // FactorContext의 생성자 또는 복사 메서드를 사용하여 새 인스턴스 생성
            FactorContext copy = new FactorContext(
                    original.getMfaSessionId(),
                    original.getPrimaryAuthentication(),
                    original.getCurrentState(),
                    original.getFlowTypeName()
            );
            copy.setVersion(original.getVersion());
            copy.setCurrentProcessingFactor(original.getCurrentProcessingFactor());
            copy.setCurrentStepId(original.getCurrentStepId());
            if (original.getCurrentFactorOptions() != null) {
                // AuthenticationProcessingOptions는 불변이거나, 복사 로직 필요
                // 여기서는 참조 복사로 가정 (주의 필요)
                copy.setCurrentFactorOptions(original.getCurrentFactorOptions());
            }
            copy.setMfaRequiredAsPerPolicy(original.isMfaRequiredAsPerPolicy());
            copy.setRetryCount(original.getRetryCount());
            copy.setLastError(original.getLastError());
            copy.setLastActivityTimestamp(original.getLastActivityTimestamp());

            // Collections - defensive copies
            original.getCompletedFactors().forEach(copy::addCompletedFactor);
            copy.setRegisteredMfaFactors(new ArrayList<>(original.getRegisteredMfaFactors()));

            original.getFactorAttemptCounts().forEach((factor, count) -> {
                for(int i=0; i < count; i++) copy.incrementAttemptCount(factor);
            });

            original.getMfaAttemptHistory().forEach(attempt -> copy.recordAttempt(attempt.getFactorType(), attempt.isSuccess(), attempt.getDetail()));

            // Attributes - 주의: 값들이 불변이거나 deep copy 필요
            // 여기서는 Map 자체는 새로 만들고, 값들은 참조 복사
            if (original.getAttributes() != null) {
                original.getAttributes().forEach(copy::setAttribute);
            }
            return copy;
        }
    }
    public enum ConflictResolution {
        NO_CONFLICT, USE_SERVER, ACCEPT_CLIENT, MERGE, FORCE_REFRESH
    }
}