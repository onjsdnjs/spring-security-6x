package io.springsecurity.springsecurity6x.security.core.mfa;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class RedisContextPersistence implements ContextPersistence {
    private final Map<String, FactorContext> store = new ConcurrentHashMap<>();

    @Override
    public FactorContext contextLoad(HttpServletRequest req) {
        String sid = req.getHeader("X-MFA-Session");
        if (sid == null) {
            sid = java.util.UUID.randomUUID().toString();
        }
        return store.computeIfAbsent(sid, k -> {
            Authentication authentication = SecurityContextHolder.getContextHolderStrategy().getContext().getAuthentication();
            FactorContext ctx = new FactorContext(authentication, null);
            ctx.getMfaSessionId();
            return ctx;
        });
    }

    @Override
    public void saveContext(FactorContext ctx, HttpServletRequest request) {

    }

    @Override
    public void deleteContext(HttpServletRequest request) {

    }
}
