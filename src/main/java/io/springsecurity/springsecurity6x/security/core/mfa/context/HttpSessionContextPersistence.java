package io.springsecurity.springsecurity6x.security.core.mfa.context;

import io.springsecurity.springsecurity6x.security.core.mfa.exception.ContextPersistenceException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component; // 컴포넌트 스캔 대상

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * HttpSession 기반 ContextPersistence 구현체
 * 단일 서버 환경에 최적화
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "security.mfa.persistence.type", havingValue = "session")
public class HttpSessionContextPersistence implements ExtendedContextPersistence {

    public static final String MFA_CONTEXT_SESSION_ATTRIBUTE_NAME = "MFA_CONTEXT";
    public static final String MFA_SESSION_ID_ATTRIBUTE_NAME = "MFA_SESSION_ID";

    private final AtomicLong contextAccessCounter = new AtomicLong(0);
    private final Map<String, Long> contextAccessTimes = new ConcurrentHashMap<>();

    @Override
    @Nullable
    public FactorContext contextLoad(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            log.trace("No HttpSession found for request. Cannot load FactorContext.");
            return null;
        }

        try {
            FactorContext context = (FactorContext) session.getAttribute(MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);

            if (context != null) {
                // 접근 통계 업데이트
                contextAccessCounter.incrementAndGet();
                contextAccessTimes.put(context.getMfaSessionId(), System.currentTimeMillis());

                // 마지막 활동 시간 업데이트
                context.updateLastActivityTimestamp();

                log.debug("FactorContext loaded from HttpSession: sessionId={}, state={}",
                        context.getMfaSessionId(), context.getCurrentState());
            }

            return context;
        } catch (Exception e) {
            log.error("Failed to load FactorContext from HttpSession", e);
            return null;
        }
    }

    @Override
    @Nullable
    public FactorContext loadContext(String mfaSessionId, HttpServletRequest request) {
        if (mfaSessionId == null) {
            return contextLoad(request);
        }

        // HttpSession에서는 현재 세션의 컨텍스트만 로드 가능
        FactorContext context = contextLoad(request);

        if (context != null && Objects.equals(context.getMfaSessionId(), mfaSessionId)) {
            return context;
        }

        log.debug("Requested MFA session ID {} does not match current session context", mfaSessionId);
        return null;
    }

    @Override
    public void saveContext(@Nullable FactorContext ctx, HttpServletRequest request) {
        HttpSession session = request.getSession(true);

        if (ctx == null) {
            // null 컨텍스트는 삭제를 의미
            session.removeAttribute(MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
            session.removeAttribute(MFA_SESSION_ID_ATTRIBUTE_NAME);
            log.debug("FactorContext removed from HttpSession");
            return;
        }

        try {
            // FactorContext 저장
            session.setAttribute(MFA_CONTEXT_SESSION_ATTRIBUTE_NAME, ctx);
            session.setAttribute(MFA_SESSION_ID_ATTRIBUTE_NAME, ctx.getMfaSessionId());

            // 접근 통계 업데이트
            contextAccessTimes.put(ctx.getMfaSessionId(), System.currentTimeMillis());

            log.debug("FactorContext saved to HttpSession: sessionId={}, state={}, version={}",
                    ctx.getMfaSessionId(), ctx.getCurrentState(), ctx.getVersion());

        } catch (Exception e) {
            log.error("Failed to save FactorContext to HttpSession", e);
            throw new ContextPersistenceException("Failed to save context to session", e);
        }
    }

    @Override
    public void deleteContext(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return;
        }

        try {
            Object mfaSessionId = session.getAttribute(MFA_SESSION_ID_ATTRIBUTE_NAME);

            session.removeAttribute(MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
            session.removeAttribute(MFA_SESSION_ID_ATTRIBUTE_NAME);

            // 통계 정리
            if (mfaSessionId instanceof String) {
                contextAccessTimes.remove(mfaSessionId);
                log.debug("FactorContext deleted from HttpSession: sessionId={}", mfaSessionId);
            }

        } catch (Exception e) {
            log.error("Failed to delete FactorContext from HttpSession", e);
        }
    }

    @Override
    public void deleteContext(String sessionId) {
        // HttpSession 기반에서는 현재 요청 컨텍스트 없이 삭제 불가
        log.warn("Cannot delete context by sessionId in HttpSession mode: {}", sessionId);
        contextAccessTimes.remove(sessionId);
    }

    @Override
    public boolean exists(String sessionId) {
        return contextAccessTimes.containsKey(sessionId);
    }

    @Override
    public void refreshTtl(String sessionId) {
        // HttpSession의 TTL은 서블릿 컨테이너에서 관리
        contextAccessTimes.put(sessionId, System.currentTimeMillis());
        log.trace("Context access time updated for session: {}", sessionId);
    }

    @Override
    public PersistenceType getPersistenceType() {
        return PersistenceType.SESSION;
    }

    /**
     * 세션 통계 정보 반환
     */
    public Map<String, Object> getSessionStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalAccess", contextAccessCounter.get());
        stats.put("activeContexts", contextAccessTimes.size());
        stats.put("persistenceType", getPersistenceType().name());
        return stats;
    }
}
