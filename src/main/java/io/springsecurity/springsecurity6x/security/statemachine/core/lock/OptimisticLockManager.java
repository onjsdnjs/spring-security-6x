package io.springsecurity.springsecurity6x.security.statemachine.core.lock;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Optimistic Lock 관리자
 * - 버전 기반 동시성 제어
 * - 상태 캐싱 및 검증
 * - 충돌 감지 및 해결
 */
@Slf4j
@Component
public class OptimisticLockManager {

    // 세션별 버전 정보
    private final Map<String, VersionInfo> versionMap = new ConcurrentHashMap<>();

    // 상태 캐시
    private final Map<String, CachedState> stateCache = new ConcurrentHashMap<>();

    // 충돌 통계
    private final AtomicLong totalConflicts = new AtomicLong(0);
    private final AtomicLong totalChecks = new AtomicLong(0);

    /**
     * 버전 확인
     */
    public boolean checkVersion(String sessionId, int expectedVersion) {
        totalChecks.incrementAndGet();

        VersionInfo versionInfo = versionMap.get(sessionId);
        if (versionInfo == null) {
            // 첫 접근
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

    /**
     * 버전 업데이트
     */
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

    /**
     * 버전 증가
     */
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

    /**
     * 캐시된 상태 조회
     */
    public MfaState getCachedState(String sessionId) {
        CachedState cached = stateCache.get(sessionId);

        if (cached != null && !cached.isExpired()) {
            cached.hitCount.incrementAndGet();
            return cached.state;
        }

        return null;
    }

    /**
     * 캐시된 FactorContext 조회
     */
    public FactorContext getCachedContext(String sessionId) {
        CachedContext cached = contextCache.get(sessionId);

        if (cached != null && !cached.isExpired()) {
            cached.hitCount.incrementAndGet();
            return cached.context;
        }

        return null;
    }

    /**
     * FactorContext 캐시 업데이트
     */
    public void updateCachedContext(String sessionId, FactorContext context) {
        contextCache.put(sessionId, new CachedContext(context));
    }
    /**
     * 상태 캐시 업데이트
     */
    public void updateCachedState(String sessionId, MfaState state) {
        stateCache.put(sessionId, new CachedState(state));
    }

    /**
     * FactorContext 캐시 무효화
     */
    public void invalidateContextCache(String sessionId) {
        contextCache.remove(sessionId);
        log.debug("Context cache invalidated for session: {}", sessionId);
    }

    // 기존 필드에 추가
    private final Map<String, CachedContext> contextCache = new ConcurrentHashMap<>();

    /**
     * 캐시 무효화
     */
    public void invalidateCache(String sessionId) {
        stateCache.remove(sessionId);
        log.debug("Cache invalidated for session: {}", sessionId);
    }

    /**
     * 전체 캐시 정리
     */
    public void clearCache(String sessionId) {
        versionMap.remove(sessionId);
        stateCache.remove(sessionId);
        contextCache.remove(sessionId); //
    }

    /**
     * 충돌 해결 전략
     */
    public ConflictResolution resolveConflict(String sessionId, int clientVersion, int serverVersion) {
        if (clientVersion == serverVersion) {
            return ConflictResolution.NO_CONFLICT;
        }

        VersionInfo info = versionMap.get(sessionId);
        if (info == null) {
            return ConflictResolution.ACCEPT_CLIENT;
        }

        // 충돌 빈도 확인
        int conflicts = info.conflictCount.get();

        if (conflicts > 10) {
            // 너무 많은 충돌 - 전체 새로고침 필요
            return ConflictResolution.FORCE_REFRESH;
        } else if (serverVersion - clientVersion > 5) {
            // 버전 차이가 큼 - 서버 버전 사용
            return ConflictResolution.USE_SERVER;
        } else {
            // 병합 시도
            return ConflictResolution.MERGE;
        }
    }

    /**
     * 통계 조회
     */
    public OptimisticLockStatistics getStatistics() {
        long checks = totalChecks.get();
        long conflicts = totalConflicts.get();

        return new OptimisticLockStatistics(
                checks,
                conflicts,
                checks > 0 ? (double) conflicts / checks : 0,
                versionMap.size(),
                stateCache.size()
        );
    }

    /**
     * 오래된 항목 정리 - 컨텍스트 캐시 포함
     */
    public void cleanup(long maxAgeMillis) {
        long cutoff = System.currentTimeMillis() - maxAgeMillis;

        // 버전 정보 정리
        versionMap.entrySet().removeIf(entry ->
                entry.getValue().lastUpdated < cutoff
        );

        // 상태 캐시 정리
        stateCache.entrySet().removeIf(entry ->
                entry.getValue().isExpired()
        );

        // ✅ 추가: 컨텍스트 캐시 정리
        contextCache.entrySet().removeIf(entry ->
                entry.getValue().isExpired()
        );

        log.debug("Cleanup completed. Version entries: {}, State cache: {}, Context cache: {}",
                versionMap.size(), stateCache.size(), contextCache.size());
    }

    /**
     * 버전 정보
     */
    private static class VersionInfo {
        final AtomicInteger version;
        final AtomicInteger conflictCount = new AtomicInteger(0);
        volatile long lastUpdated;

        VersionInfo(int initialVersion) {
            this.version = new AtomicInteger(initialVersion);
            this.lastUpdated = System.currentTimeMillis();
        }
    }

    /**
     * 캐시된 상태
     */
    private static class CachedState {
        final MfaState state;
        final long cachedAt;
        final AtomicInteger hitCount = new AtomicInteger(0);

        CachedState(MfaState state) {
            this.state = state;
            this.cachedAt = System.currentTimeMillis();
        }

        boolean isExpired() {
            return System.currentTimeMillis() - cachedAt > TimeUnit.MINUTES.toMillis(5);
        }
    }

    /**
     * 충돌 해결 전략
     */
    public enum ConflictResolution {
        NO_CONFLICT,      // 충돌 없음
        USE_SERVER,       // 서버 버전 사용
        ACCEPT_CLIENT,    // 클라이언트 버전 수락
        MERGE,            // 병합 시도
        FORCE_REFRESH     // 전체 새로고침
    }

    /**
     * Optimistic Lock 통계
     */
    public static class OptimisticLockStatistics {
        private final long totalChecks;
        private final long totalConflicts;
        private final double conflictRate;
        private final int activeVersions;
        private final int cachedStates;

        public OptimisticLockStatistics(long totalChecks, long totalConflicts,
                                        double conflictRate, int activeVersions,
                                        int cachedStates) {
            this.totalChecks = totalChecks;
            this.totalConflicts = totalConflicts;
            this.conflictRate = conflictRate;
            this.activeVersions = activeVersions;
            this.cachedStates = cachedStates;
        }

        // Getters
        public long getTotalChecks() { return totalChecks; }
        public long getTotalConflicts() { return totalConflicts; }
        public double getConflictRate() { return conflictRate; }
        public int getActiveVersions() { return activeVersions; }
        public int getCachedStates() { return cachedStates; }

        @Override
        public String toString() {
            return String.format(
                    "OptimisticLockStats[checks=%d, conflicts=%d, rate=%.2f%%, versions=%d, cached=%d]",
                    totalChecks, totalConflicts, conflictRate * 100, activeVersions, cachedStates
            );
        }
    }

    /**
     * 캐시된 FactorContext
     */
    private static class CachedContext {
        final FactorContext context;
        final long cachedAt;
        final AtomicInteger hitCount = new AtomicInteger(0);

        CachedContext(FactorContext context) {
            // ✅ 중요: 깊은 복사로 캐시 무결성 보장
            this.context = createContextCopy(context);
            this.cachedAt = System.currentTimeMillis();
        }

        boolean isExpired() {
            return System.currentTimeMillis() - cachedAt > TimeUnit.MINUTES.toMillis(5);
        }

        /**
         * FactorContext 안전한 복사
         */
        private FactorContext createContextCopy(FactorContext original) {
            // 새로운 FactorContext 생성 (참조 공유 방지)
            FactorContext copy = new FactorContext(
                    original.getMfaSessionId(),
                    original.getPrimaryAuthentication(),
                    original.getCurrentState(),
                    original.getFlowTypeName()
            );

            // 핵심 필드들만 복사 (성능 고려)
            copy.setCurrentProcessingFactor(original.getCurrentProcessingFactor());
            copy.setCurrentStepId(original.getCurrentStepId());
            copy.setMfaRequiredAsPerPolicy(original.isMfaRequiredAsPerPolicy());
            copy.setRetryCount(original.getRetryCount());
            copy.setLastError(original.getLastError());

            // 버전 동기화
            while (copy.getVersion() < original.getVersion()) {
                copy.incrementVersion();
            }

            return copy;
        }
    }

}

