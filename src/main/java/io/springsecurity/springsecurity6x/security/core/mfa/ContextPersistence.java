package io.springsecurity.springsecurity6x.security.core.mfa;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import jakarta.servlet.http.HttpServletRequest;

public interface ContextPersistence {
    FactorContext loadOrInit(HttpServletRequest req);
    void save(FactorContext ctx);
    void delete(FactorContext ctx);
}
