package io.springsecurity.springsecurity6x.security.core.session.impl;

import io.springsecurity.springsecurity6x.security.core.session.MfaSessionRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * InMemory 기반 MFA 세션 Repository - 개발/테스트 환경 최적화
 */
@Slf4j
@Repository
@ConditionalOnProperty(name = "security.mfa.session.storage-type", havingValue = "memory")
public class InMemoryMfaRepository implements MfaSessionRepository {

    private final java.util.concurrent.ConcurrentHashMap<String, SessionEntry> sessions = new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.concurrent.ScheduledExecutorService cleanupExecutor = java.util.concurrent.Executors.newSingleThreadScheduledExecutor();
    private final SecureRandom secureRandom = new SecureRandom();
    private Duration sessionTimeout = Duration.ofMinutes(30);
    private final AtomicLong totalSessionsCreated = new AtomicLong(0);
    private final AtomicLong sessionCollisions = new AtomicLong(0);

    public InMemoryMfaRepository() {
        cleanupExecutor.scheduleAtFixedRate(this::cleanupExpiredSessions, 5, 5, java.util.concurrent.TimeUnit.MINUTES);
    }

    @Override
    public void storeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response) {
        SessionEntry entry = new SessionEntry(sessionId, java.time.Instant.now().plus(sessionTimeout));

        if (sessions.putIfAbsent(sessionId, entry) != null) {
            sessionCollisions.incrementAndGet();
            throw new SessionIdGenerationException("Session ID already exists in memory: " + sessionId);
        }

        totalSessionsCreated.incrementAndGet();
        log.debug("MFA session stored in memory: {}", sessionId);
    }

    @Override
    @Nullable
    public String getSessionId(HttpServletRequest request) {
        return (String) request.getAttribute("MFA_SESSION_ID");
    }

    @Override
    public void removeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response) {
        sessions.remove(sessionId);
        log.debug("MFA session removed from memory: {}", sessionId);
    }

    @Override
    public void refreshSession(String sessionId) {
        SessionEntry entry = sessions.get(sessionId);
        if (entry != null) {
            entry.expiryTime = java.time.Instant.now().plus(sessionTimeout);
            log.trace("Memory session refreshed for: {}", sessionId);
        }
    }

    @Override
    public boolean existsSession(String sessionId) {
        SessionEntry entry = sessions.get(sessionId);
        if (entry == null) {
            return false;
        }

        if (entry.isExpired()) {
            sessions.remove(sessionId);
            return false;
        }

        return true;
    }

    @Override
    public void setSessionTimeout(Duration timeout) {
        this.sessionTimeout = timeout;
        log.info("Memory session timeout set to: {}", timeout);
    }

    @Override
    public String getRepositoryType() {
        return "IN_MEMORY";
    }

    // === 개선된 인터페이스 구현 ===

    @Override
    public String generateUniqueSessionId(@Nullable String baseId, HttpServletRequest request) {
        for (int attempt = 0; attempt < 10; attempt++) {
            String sessionId = generateMemoryOptimizedId(baseId, request);

            if (isSessionIdUnique(sessionId)) {
                return sessionId;
            }

            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        throw new SessionIdGenerationException("Failed to generate unique session ID for memory storage");
    }

    @Override
    public boolean isSessionIdUnique(String sessionId) {
        return !sessions.containsKey(sessionId);
    }

    @Override
    public String resolveSessionIdCollision(String originalId, HttpServletRequest request, int maxAttempts) {
        sessionCollisions.incrementAndGet();

        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            String resolvedId = createMemoryCollisionResolvedId(originalId, attempt);
            if (isSessionIdUnique(resolvedId)) {
                return resolvedId;
            }
        }

        throw new SessionIdGenerationException("Failed to resolve memory session ID collision");
    }

    @Override
    public boolean isValidSessionIdFormat(String sessionId) {
        return StringUtils.hasText(sessionId) &&
                sessionId.matches("^[a-zA-Z0-9_-]{16,64}$");
    }

    @Override
    public boolean supportsDistributedSync() {
        return false;
    }

    @Override
    public int getSessionIdSecurityScore(String sessionId) {
        if (!StringUtils.hasText(sessionId)) {
            return 0;
        }

        int score = 0;

        if (sessionId.length() >= 32) score += 30;
        else if (sessionId.length() >= 24) score += 25;
        else if (sessionId.length() >= 16) score += 20;

        score += 35; // 메모리 기반 보너스

        if (isSessionIdUnique(sessionId)) {
            score += 35;
        }

        return Math.min(100, score);
    }

    @Override
    public SessionStats getSessionStats() {
        cleanupExpiredSessions();

        return new SessionStats(
                sessions.size(),
                totalSessionsCreated.get(),
                sessionCollisions.get(),
                sessionTimeout.toSeconds() * 0.7,
                getRepositoryType()
        );
    }

    // === 유틸리티 메서드들 ===

    private String generateMemoryOptimizedId(@Nullable String baseId, HttpServletRequest request) {
        long timestamp = System.currentTimeMillis();
        int threadId = Thread.currentThread().hashCode();

        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        String randomPart = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        String combined = timestamp + "_" + threadId + "_" + randomPart;
        if (StringUtils.hasText(baseId)) {
            combined = baseId.substring(0, Math.min(8, baseId.length())) + "_" + combined;
        }

        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(combined.getBytes(StandardCharsets.UTF_8));
    }

    private String createMemoryCollisionResolvedId(String originalId, int attempt) {
        long nanoTime = System.nanoTime();
        String suffix = String.valueOf(nanoTime + attempt * 1000000);

        String resolved = originalId.substring(0, Math.min(12, originalId.length())) +
                "_" + suffix;

        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(resolved.getBytes(StandardCharsets.UTF_8));
    }

    private void cleanupExpiredSessions() {
        java.time.Instant now = java.time.Instant.now();
        int removed = 0;

        var iterator = sessions.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            if (entry.getValue().expiryTime.isBefore(now)) {
                iterator.remove();
                removed++;
            }
        }

        if (removed > 0) {
            log.debug("Cleaned up {} expired sessions from memory", removed);
        }
    }

    private static class SessionEntry {
        final String sessionId;
        volatile java.time.Instant expiryTime;

        SessionEntry(String sessionId, java.time.Instant expiryTime) {
            this.sessionId = sessionId;
            this.expiryTime = expiryTime;
        }

        boolean isExpired() {
            return java.time.Instant.now().isAfter(expiryTime);
        }
    }
}