package io.springsecurity.springsecurity6x.security.core.session.impl;

import io.springsecurity.springsecurity6x.security.core.session.MfaSessionRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Repository;

import java.time.Duration;

/**
 * HTTP Session 기반 MFA 세션 Repository
 * - 단일 서버 환경에 최적화
 * - 기존 방식과 완전 호환
 */

@Slf4j
@Repository
@ConditionalOnProperty(name = "security.mfa.session.storage-type", havingValue = "http-session", matchIfMissing = true)
public class HttpSessionMfaRepository implements MfaSessionRepository {

    private static final String MFA_SESSION_ID_ATTRIBUTE = "MFA_SESSION_ID";
    private Duration sessionTimeout = Duration.ofMinutes(30);

    @Override
    public void storeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response) {
        HttpSession session = request.getSession(true);
        session.setAttribute(MFA_SESSION_ID_ATTRIBUTE, sessionId);

        // HTTP Session의 경우 서버에서 타임아웃 관리
        session.setMaxInactiveInterval((int) sessionTimeout.toSeconds());

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
            log.debug("MFA session removed from HTTP Session: {}", sessionId);
        }
    }

    @Override
    public void refreshSession(String sessionId) {
        // HTTP Session은 자동으로 갱신되므로 별도 작업 불필요
        log.trace("HTTP Session auto-refresh for: {}", sessionId);
    }

    @Override
    public boolean existsSession(String sessionId) {
        // HTTP Session 기반에서는 getSessionId로 존재 여부 확인
        // 실제로는 요청 컨텍스트가 필요하므로 제한적
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
}
