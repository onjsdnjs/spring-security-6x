package io.springsecurity.springsecurity6x.security.core.session.impl;

import io.springsecurity.springsecurity6x.security.core.session.MfaSessionRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicLong;

/**
 * HTTP Session 기반 MFA 세션 Repository - 단일서버 최적화
 */
@Slf4j
@Repository
@ConditionalOnProperty(name = "security.mfa.session.storage-type", havingValue = "http-session", matchIfMissing = true)
public class HttpSessionMfaRepository implements MfaSessionRepository {

    private static final String MFA_SESSION_ID_ATTRIBUTE = "MFA_SESSION_ID";
    private static final String SESSION_CREATION_TIME_ATTRIBUTE = "MFA_SESSION_CREATION_TIME";
    private Duration sessionTimeout = Duration.ofMinutes(30);
    private final SecureRandom secureRandom = new SecureRandom();
    private final AtomicLong totalSessionsCreated = new AtomicLong(0);
    private final AtomicLong sessionCollisions = new AtomicLong(0);

    @Override
    public void storeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response) {
        HttpSession session = request.getSession(true);
        session.setAttribute(MFA_SESSION_ID_ATTRIBUTE, sessionId);
        session.setAttribute(SESSION_CREATION_TIME_ATTRIBUTE, System.currentTimeMillis());
        session.setMaxInactiveInterval((int) sessionTimeout.toSeconds());

        totalSessionsCreated.incrementAndGet();
        log.debug("MFA session stored in HTTP Session: {}", sessionId);
    }

    @Override
    @Nullable
    public String getSessionId(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        return (String) session.getAttribute(MFA_SESSION_ID_ATTRIBUTE);
    }

    @Override
    public void removeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(MFA_SESSION_ID_ATTRIBUTE);
            session.removeAttribute(SESSION_CREATION_TIME_ATTRIBUTE);
            log.debug("MFA session removed from HTTP Session: {}", sessionId);
        }
    }

    @Override
    public void refreshSession(String sessionId) {
        log.trace("HTTP Session auto-refresh for: {}", sessionId);
    }

    @Override
    public boolean existsSession(String sessionId) {
        return sessionId != null;
    }

    @Override
    public void setSessionTimeout(Duration timeout) {
        this.sessionTimeout = timeout;
        log.info("HTTP Session timeout set to: {}", timeout);
    }

    @Override
    public String getRepositoryType() {
        return "HTTP_SESSION";
    }

    // === 개선된 인터페이스 구현 ===

    @Override
    public String generateUniqueSessionId(@Nullable String baseId, HttpServletRequest request) {
        if (StringUtils.hasText(baseId)) {
            String enhanced = enhanceSessionId(baseId, request);
            if (isValidSessionIdFormat(enhanced)) {
                return enhanced;
            }
        }
        return generateHttpSessionOptimizedId(request);
    }

    @Override
    public boolean isSessionIdUnique(String sessionId) {
        return isValidSessionIdFormat(sessionId);
    }

    @Override
    public String resolveSessionIdCollision(String originalId, HttpServletRequest request, int maxAttempts) {
        sessionCollisions.incrementAndGet();

        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            String resolvedId = createHttpSessionCollisionResolvedId(originalId, attempt, request);
            if (isValidSessionIdFormat(resolvedId)) {
                log.debug("HTTP Session ID collision resolved: {} -> {} (attempt: {})",
                        originalId, resolvedId, attempt + 1);
                return resolvedId;
            }
        }

        throw new SessionIdGenerationException(
                "Failed to resolve HTTP session ID collision after " + maxAttempts + " attempts");
    }

    @Override
    public boolean isValidSessionIdFormat(String sessionId) {
        if (!StringUtils.hasText(sessionId)) {
            return false;
        }
        return sessionId.matches("^[a-zA-Z0-9_-]{32,}$") && sessionId.length() <= 128;
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

        if (sessionId.length() >= 32) score += 25;
        else if (sessionId.length() >= 24) score += 20;
        else if (sessionId.length() >= 16) score += 15;

        if (sessionId.chars().allMatch(c -> Character.isLetterOrDigit(c) || c == '_' || c == '-')) {
            score += 25;
        }

        score += Math.min(25, estimateEntropy(sessionId));
        score += 25; // 단일 서버 환경 보너스

        return Math.min(100, score);
    }

    @Override
    public SessionStats getSessionStats() {
        return new SessionStats(
                0,
                totalSessionsCreated.get(),
                sessionCollisions.get(),
                sessionTimeout.toSeconds() * 0.5,
                getRepositoryType()
        );
    }

    // === 유틸리티 메서드들 ===

    private String generateHttpSessionOptimizedId(HttpServletRequest request) {
        String timestamp = String.valueOf(System.currentTimeMillis());
        String serverInfo = request.getServerName() + ":" + request.getServerPort();

        byte[] randomBytes = new byte[24];
        secureRandom.nextBytes(randomBytes);
        String randomPart = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        String combined = timestamp + "_" + serverInfo.hashCode() + "_" + randomPart;

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(combined.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(combined.getBytes(StandardCharsets.UTF_8));
        }
    }

    private String enhanceSessionId(String baseId, HttpServletRequest request) {
        String sessionInfo = request.getSession().getId();
        String clientInfo = request.getRemoteAddr();

        String enhanced = baseId + "_" + sessionInfo.hashCode() + "_" + clientInfo.hashCode();
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(enhanced.getBytes(StandardCharsets.UTF_8));
    }

    private String createHttpSessionCollisionResolvedId(String originalId, int attempt, HttpServletRequest request) {
        String suffix = String.valueOf(System.nanoTime() + attempt * 1000);
        String sessionId = request.getSession().getId();

        String resolved = originalId.substring(0, Math.min(16, originalId.length())) +
                "_" + sessionId.hashCode() + "_" + suffix;

        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(resolved.getBytes(StandardCharsets.UTF_8));
    }

    private int estimateEntropy(String sessionId) {
        if (sessionId.length() == 0) return 0;

        int uniqueChars = (int) sessionId.chars().distinct().count();
        double entropy = (double) uniqueChars / sessionId.length() * 25;

        return (int) Math.min(25, entropy);
    }
}