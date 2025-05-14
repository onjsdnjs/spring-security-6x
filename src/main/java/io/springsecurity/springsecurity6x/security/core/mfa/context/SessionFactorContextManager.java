package io.springsecurity.springsecurity6x.security.core.mfa.context;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

public class SessionFactorContextManager implements FactorContextManager {
    private static final String ATTR = "MFA_CONTEXT";

    @Override
    public FactorContext load(HttpServletRequest req) {
        HttpSession sess = req.getSession(true);
        FactorContext ctx = (FactorContext) sess.getAttribute(ATTR);
        if (ctx == null) {
            ctx = new FactorContext();
            sess.setAttribute(ATTR, ctx);
        }
        return ctx;
    }

    @Override
    public void save(FactorContext ctx, HttpServletRequest req) {
        req.getSession().setAttribute(ATTR, ctx);
    }

    @Override
    public void clear(HttpServletRequest req) {
        req.getSession().removeAttribute(ATTR);
    }
}
