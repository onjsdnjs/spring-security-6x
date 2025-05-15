package io.springsecurity.springsecurity6x.security.core.mfa;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class HttpSessionContextPersistence implements ContextPersistence {

    private static final String MFA_CONTEXT_ATTR = "MFA_FACTOR_CONTEXT_V2"; // 버전 명시 또는 상수명 유지

    /**
     * HTTP 세션에서 FactorContext를 로드합니다.
     * 세션이 없거나 FactorContext가 저장되어 있지 않으면 null을 반환합니다.
     * 이 메소드는 FactorContext를 새로 생성하지 않습니다.
     *
     * @param request HttpServletRequest 객체
     * @return 세션에 저장된 FactorContext 객체, 또는 없는 경우 null
     */
    @Override
    @Nullable // FactorContext가 없을 수 있음을 명시
    public FactorContext contextLoad(HttpServletRequest request) {
        HttpSession session = request.getSession(false); // 세션이 없으면 새로 생성하지 않음
        if (session == null) {
            log.trace("No HttpSession found, cannot load FactorContext.");
            return null;
        }

        Object contextFromSession = session.getAttribute(MFA_CONTEXT_ATTR);
        if (contextFromSession == null) {
            log.trace("No FactorContext found in session attribute '{}' for session ID: {}", MFA_CONTEXT_ATTR, session.getId());
            return null;
        }

        if (!(contextFromSession instanceof FactorContext)) {
            log.warn("Object found in session attribute '{}' is not an instance of FactorContext. Actual type: {}. Session ID: {}. Removing invalid attribute.",
                    MFA_CONTEXT_ATTR, contextFromSession.getClass().getName(), session.getId());
            session.removeAttribute(MFA_CONTEXT_ATTR); // 잘못된 타입의 속성 제거
            return null;
        }

        FactorContext factorContext = (FactorContext) contextFromSession;
        log.debug("FactorContext loaded from session. Session ID: {}, Context ID: {}, Current State: {}",
                session.getId(), factorContext.getMfaSessionId(), factorContext.getCurrentState());
        return factorContext;
    }

    /**
     * FactorContext를 HTTP 세션에 저장합니다.
     * FactorContext가 null이면 세션에서 해당 속성을 제거합니다.
     *
     * @param ctx     저장할 FactorContext 객체 (null일 경우 세션에서 해당 속성 제거)
     * @param request HttpServletRequest 객체
     */
    @Override
    public void saveContext(@Nullable FactorContext ctx, HttpServletRequest request) {
        // saveContext는 요청 객체를 직접 받으므로 RequestContextHolder 불필요
        HttpSession session = request.getSession(true); // 컨텍스트 저장이므로 세션이 없으면 생성

        if (ctx == null) {
            log.debug("FactorContext is null. Removing attribute '{}' from session. Session ID: {}", MFA_CONTEXT_ATTR, session.getId());
            session.removeAttribute(MFA_CONTEXT_ATTR);
        } else {
            session.setAttribute(MFA_CONTEXT_ATTR, ctx);
            log.debug("FactorContext saved to session. Session ID: {}, Context ID: {}, Current State: {}",
                    session.getId(), ctx.getMfaSessionId(), ctx.getCurrentState());
        }
    }

    /**
     * HTTP 세션에서 FactorContext를 제거합니다.
     *
     * @param request HttpServletRequest 객체
     */
    @Override
    public void deleteContext(HttpServletRequest request) { // 메소드명 변경 (delete -> deleteContext) 및 FactorContext 파라미터 제거
        HttpSession session = request.getSession(false);
        if (session != null) {
            Object removedContext = session.getAttribute(MFA_CONTEXT_ATTR);
            session.removeAttribute(MFA_CONTEXT_ATTR);
            if (removedContext instanceof FactorContext fc) { // 패턴 변수 바인딩 사용
                log.debug("FactorContext cleared from session. Session ID: {}, Context ID: {}", session.getId(), fc.getMfaSessionId());
            } else if (removedContext != null) {
                log.debug("Removed attribute '{}' (was not FactorContext) from session. Session ID: {}", MFA_CONTEXT_ATTR, session.getId());
            } else {
                log.trace("No FactorContext to clear in session attribute '{}' for session ID: {}", MFA_CONTEXT_ATTR, session.getId());
            }
        } else {
            log.trace("No HttpSession found, cannot clear FactorContext.");
        }
    }
}
