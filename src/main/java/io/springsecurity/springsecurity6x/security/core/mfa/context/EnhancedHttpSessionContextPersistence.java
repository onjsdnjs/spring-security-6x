package io.springsecurity.springsecurity6x.security.core.mfa.context;

import io.springsecurity.springsecurity6x.security.core.mfa.config.ContextPersistenceProperties;
import io.springsecurity.springsecurity6x.security.core.mfa.exception.ContextPersistenceException;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 향상된 HttpSession 기반 ContextPersistence
 */
@Slf4j
public class EnhancedHttpSessionContextPersistence extends HttpSessionContextPersistence {

    private final ContextPersistenceProperties.SessionConfig config;
    private final AtomicInteger activeSessions = new AtomicInteger(0);
    private final Map<String, SessionInfo> sessionInfoMap = new ConcurrentHashMap<>();

    public EnhancedHttpSessionContextPersistence(ContextPersistenceProperties.SessionConfig config) {
        this.config = config;
        log.info("Enhanced HttpSession ContextPersistence initialized with config: {}", config);
    }

    @Override
    public void saveContext(@Nullable FactorContext ctx, HttpServletRequest request) {
        // 최대 세션 수 체크
        if (ctx != null && activeSessions.get() >= config.getMaxConcurrentSessions()) {
            cleanupExpiredSessions();

            if (activeSessions.get() >= config.getMaxConcurrentSessions()) {
                throw new ContextPersistenceException(
                        "Maximum concurrent sessions exceeded: " + config.getMaxConcurrentSessions());
            }
        }

        super.saveContext(ctx, request);

        // 세션 정보 업데이트
        if (ctx != null) {
            sessionInfoMap.put(ctx.getMfaSessionId(), new SessionInfo(
                    ctx.getMfaSessionId(),
                    ctx.getUsername(),
                    System.currentTimeMillis(),
                    ctx.getCurrentState()
            ));
            activeSessions.incrementAndGet();
        }
    }

    @Override
    public void deleteContext(HttpServletRequest request) {
        FactorContext ctx = contextLoad(request);
        if (ctx != null) {
            sessionInfoMap.remove(ctx.getMfaSessionId());
            activeSessions.decrementAndGet();
        }

        super.deleteContext(request);
    }

    /**
     * 만료된 세션 정리
     */
    private void cleanupExpiredSessions() {
        long now = System.currentTimeMillis();
        long timeoutMs = config.getTimeoutMinutes() * 60 * 1000L;

        sessionInfoMap.entrySet().removeIf(entry -> {
            SessionInfo info = entry.getValue();
            if (now - info.getLastAccessTime() > timeoutMs) {
                activeSessions.decrementAndGet();
                log.debug("Cleaned up expired session: {}", entry.getKey());
                return true;
            }
            return false;
        });
    }

    /**
     * 세션 통계 조회
     */
    @Override
    public Map<String, Object> getSessionStatistics() {
        Map<String, Object> stats = super.getSessionStatistics();
        stats.put("activeSessionsCount", activeSessions.get());
        stats.put("maxConcurrentSessions", config.getMaxConcurrentSessions());
        stats.put("timeoutMinutes", config.getTimeoutMinutes());
        return stats;
    }

    /**
     * 세션 정보 내부 클래스
     */
    @Data
    private static class SessionInfo {
        private final String sessionId;
        private final String username;
        private final long lastAccessTime;
        private final MfaState currentState;
    }
}
