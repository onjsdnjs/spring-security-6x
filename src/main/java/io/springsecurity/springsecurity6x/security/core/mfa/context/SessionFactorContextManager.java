package io.springsecurity.springsecurity6x.security.core.mfa.context;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable; // Nullable 어노테이션 추가
import java.util.Objects;

/**
 * HTTP 세션을 사용하여 FactorContext를 관리하는 FactorContextManager 구현체입니다.
 * 이 클래스는 FactorContext의 생성 책임을 가지지 않으며,
 * 단순히 세션과의 저장, 로드, 삭제 작업만 수행합니다.
 */
@Slf4j
public class SessionFactorContextManager implements FactorContextManager {

    /**
     * HTTP 세션에 FactorContext를 저장할 때 사용되는 속성 이름입니다.
     */
    public static final String MFA_CONTEXT_SESSION_ATTRIBUTE_NAME = "MFA_CONTEXT_V1"; // 상수명 변경 및 버전 명시

    /**
     * HTTP 세션에서 FactorContext를 로드합니다.
     * 세션이 없거나 FactorContext가 저장되어 있지 않으면 null을 반환합니다.
     *
     * @param req HttpServletRequest 객체 (null이 아니어야 함)
     * @return 세션에 저장된 FactorContext 객체, 또는 세션이나 속성이 없는 경우 null
     */
    @Override
    @Nullable
    public FactorContext load(HttpServletRequest req) {
        Objects.requireNonNull(req, "HttpServletRequest cannot be null for loading FactorContext.");
        HttpSession session = req.getSession(false); // 세션이 없으면 새로 생성하지 않음

        if (session == null) {
            log.trace("[SessionFactorContextManager] No HttpSession found for request. Cannot load FactorContext.");
            return null;
        }

        Object contextFromSession = session.getAttribute(MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);

        if (contextFromSession == null) {
            log.trace("[SessionFactorContextManager] No FactorContext found in session attribute '{}' for session ID: {}", MFA_CONTEXT_SESSION_ATTRIBUTE_NAME, session.getId());
            return null;
        }

        if (!(contextFromSession instanceof FactorContext)) {
            log.warn("[SessionFactorContextManager] Object found in session attribute '{}' is not an instance of FactorContext. Actual type: {}. Session ID: {}. Removing invalid attribute.",
                    MFA_CONTEXT_SESSION_ATTRIBUTE_NAME, contextFromSession.getClass().getName(), session.getId());
            session.removeAttribute(MFA_CONTEXT_SESSION_ATTRIBUTE_NAME); // 잘못된 타입의 속성 제거
            return null;
        }

        FactorContext factorContext = (FactorContext) contextFromSession;
        log.debug("[SessionFactorContextManager] FactorContext loaded from session. Session ID: {}, Context ID: {}", session.getId(), factorContext.getMfaSessionId());
        return factorContext;
    }

    /**
     * FactorContext를 HTTP 세션에 저장합니다.
     * FactorContext가 null이면 세션에서 해당 속성을 제거합니다.
     *
     * @param ctx 저장할 FactorContext 객체 (null일 경우 세션에서 해당 속성 제거)
     * @param req HttpServletRequest 객체 (null이 아니어야 함)
     */
    @Override
    public void save(@Nullable FactorContext ctx, HttpServletRequest req) {
        Objects.requireNonNull(req, "HttpServletRequest cannot be null for saving FactorContext.");
        HttpSession session = req.getSession(true); // 컨텍스트 저장이므로 세션이 없으면 생성

        if (ctx == null) {
            log.debug("[SessionFactorContextManager] FactorContext is null. Removing attribute '{}' from session. Session ID: {}", MFA_CONTEXT_SESSION_ATTRIBUTE_NAME, session.getId());
            session.removeAttribute(MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        } else {
            session.setAttribute(MFA_CONTEXT_SESSION_ATTRIBUTE_NAME, ctx);
            log.debug("[SessionFactorContextManager] FactorContext saved to session. Session ID: {}, Context ID: {}", session.getId(), ctx.getMfaSessionId());
        }
    }

    /**
     * HTTP 세션에서 FactorContext를 제거합니다.
     *
     * @param req HttpServletRequest 객체 (null이 아니어야 함)
     */
    @Override
    public void clear(HttpServletRequest req) {
        Objects.requireNonNull(req, "HttpServletRequest cannot be null for clearing FactorContext.");
        HttpSession session = req.getSession(false); // 세션이 없으면 아무것도 하지 않음

        if (session != null) {
            Object removedContext = session.getAttribute(MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
            session.removeAttribute(MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
            if (removedContext instanceof FactorContext) {
                log.debug("[SessionFactorContextManager] FactorContext cleared from session. Session ID: {}, Context ID: {}", session.getId(), ((FactorContext) removedContext).getMfaSessionId());
            } else if (removedContext != null) {
                log.debug("[SessionFactorContextManager] Removed attribute '{}' (was not FactorContext) from session. Session ID: {}", MFA_CONTEXT_SESSION_ATTRIBUTE_NAME, session.getId());
            } else {
                log.trace("[SessionFactorContextManager] No FactorContext to clear in session attribute '{}' for session ID: {}", MFA_CONTEXT_SESSION_ATTRIBUTE_NAME, session.getId());
            }
        } else {
            log.trace("[SessionFactorContextManager] No HttpSession found, cannot clear FactorContext.");
        }
    }
}

