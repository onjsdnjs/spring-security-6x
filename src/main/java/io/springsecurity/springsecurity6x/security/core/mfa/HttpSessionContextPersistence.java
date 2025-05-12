package io.springsecurity.springsecurity6x.security.core.mfa;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

public class HttpSessionContextPersistence implements ContextPersistence {

    private static final String ATTR = "MFA_CTX";

    @Override
    public FactorContext loadOrInit(HttpServletRequest req) {
        HttpSession session = req.getSession(true);
        FactorContext ctx = (FactorContext) session.getAttribute(ATTR);
        if (ctx == null) {
            ctx = new FactorContext();
            ctx.setSessionId(session.getId());
            session.setAttribute(ATTR, ctx);
        }
        return ctx;
    }

    @Override
    public void save(FactorContext ctx) {
        // HttpSession에 이미 저장되어 있으므로 별도 처리 불필요
    }

    @Override
    public void delete(FactorContext ctx) {
        // HttpServletRequest를 통해 세션을 획득하고 컨텍스트를 제거
        ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs != null) {
            HttpServletRequest req = attrs.getRequest();
            HttpSession session = req.getSession(false);
            if (session != null) {
                session.removeAttribute(ATTR);
            }
        }
    }
}
