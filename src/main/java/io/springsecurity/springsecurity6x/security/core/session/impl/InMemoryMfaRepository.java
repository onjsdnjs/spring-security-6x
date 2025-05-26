package io.springsecurity.springsecurity6x.security.core.session.impl;

import io.springsecurity.springsecurity6x.security.core.session.MfaSessionRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Slf4j
@Repository
@ConditionalOnProperty(name = "security.mfa.session.storage-type", havingValue = "memory")
public class InMemoryMfaRepository implements MfaSessionRepository {

    private final ConcurrentHashMap<String, SessionEntry> sessions = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupExecutor = Executors.newSingleThreadScheduledExecutor();
    private Duration sessionTimeout = Duration.ofMinutes(30);

    public InMemoryMfaRepository() {
        // 5분마다 만료된 세션 정리
        cleanupExecutor.scheduleAtFixedRate(this::cleanupExpiredSessions, 5, 5, TimeUnit.MINUTES);
    }

    @Override
    public void storeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response) {
        SessionEntry entry = new SessionEntry(sessionId, Instant.now().plus(sessionTimeout));
        sessions.put(sessionId, entry);

        log.debug("MFA session stored in memory: {}", sessionId);
    }

    @Override
    @Nullable
    public String getSessionId(HttpServletRequest request) {
        // 메모리 기반에서는 요청 속성에서 조회
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
            entry.expiryTime = Instant.now().plus(sessionTimeout);
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

    private void cleanupExpiredSessions() {
        Instant now = Instant.now();
        sessions.entrySet().removeIf(entry -> entry.getValue().expiryTime.isBefore(now));
    }

    private static class SessionEntry {
        final String sessionId;
        volatile Instant expiryTime;

        SessionEntry(String sessionId, Instant expiryTime) {
            this.sessionId = sessionId;
            this.expiryTime = expiryTime;
        }

        boolean isExpired() {
            return Instant.now().isAfter(expiryTime);
        }
    }
}