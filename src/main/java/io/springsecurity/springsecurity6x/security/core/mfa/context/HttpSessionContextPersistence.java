package io.springsecurity.springsecurity6x.security.core.mfa.context;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component; // 컴포넌트 스캔 대상

@Slf4j
@Component
public class HttpSessionContextPersistence implements ContextPersistence {

    public static final String MFA_CONTEXT_SESSION_ATTRIBUTE_NAME = "MFA_SESSION_CONTEXT_V1"; // 상수명 유지 (V1은 예시)

    @Override
    @Nullable
    public FactorContext contextLoad(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            log.trace("No HttpSession found for request. Cannot load FactorContext.");
            return null;
        }

        Object contextFromSession = session.getAttribute(MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);

        if (contextFromSession == null) {
            log.trace("No FactorContext found in session attribute '{}' for session ID: {}", MFA_CONTEXT_SESSION_ATTRIBUTE_NAME, session.getId());
            return null;
        }

        if (!(contextFromSession instanceof FactorContext factorContext)) { // 패턴 변수 바인딩
            log.warn("Object found in session attribute '{}' is not an instance of FactorContext. Actual type: {}. Session ID: {}. Removing invalid attribute.",
                    MFA_CONTEXT_SESSION_ATTRIBUTE_NAME, contextFromSession.getClass().getName(), session.getId());
            session.removeAttribute(MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
            return null;
        }

        log.debug("FactorContext loaded from session. Session ID: {}, Context ID: {}, Current Context State: {}",
                session.getId(), factorContext.getMfaSessionId(), factorContext.getCurrentState());
        return factorContext;
    }

    @Override
    public void saveContext(@Nullable FactorContext ctx, HttpServletRequest request) {
        HttpSession session = request.getSession(true); // 컨텍스트 저장이므로 세션이 없으면 생성

        if (ctx == null) {
            log.debug("FactorContext is null. Removing attribute '{}' from session. Session ID: {}", MFA_CONTEXT_SESSION_ATTRIBUTE_NAME, session.getId());
            session.removeAttribute(MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        } else {
            session.setAttribute(MFA_CONTEXT_SESSION_ATTRIBUTE_NAME, ctx);
            log.debug("FactorContext saved to session. Session ID: {}, Context ID: {}, New Context State: {}",
                    session.getId(), ctx.getMfaSessionId(), ctx.getCurrentState());
        }
    }

    @Override
    public void deleteContext(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            Object removedContext = session.getAttribute(MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
            session.removeAttribute(MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
            if (removedContext instanceof FactorContext fc) {
                log.debug("FactorContext cleared from session. Session ID: {}, Context ID: {}", session.getId(), fc.getMfaSessionId());
            } else if (removedContext != null) {
                log.debug("Removed attribute '{}' (was not FactorContext) from session. Session ID: {}", MFA_CONTEXT_SESSION_ATTRIBUTE_NAME, session.getId());
            } else {
                log.trace("No FactorContext to clear in session attribute '{}' for session ID: {}", MFA_CONTEXT_SESSION_ATTRIBUTE_NAME, session.getId());
            }
        } else {
            log.trace("No HttpSession found, cannot clear FactorContext.");
        }
    }
}
