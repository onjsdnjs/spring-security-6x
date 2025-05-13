package io.springsecurity.springsecurity6x.security.core.mfa;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import jakarta.servlet.http.HttpServletRequest;

public interface ContextPersistence {
    FactorContext contextLoad(HttpServletRequest req);
    void saveContext(FactorContext ctx);
    void delete(FactorContext ctx);
}
