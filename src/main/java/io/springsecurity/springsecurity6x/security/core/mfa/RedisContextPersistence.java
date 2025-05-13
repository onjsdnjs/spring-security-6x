package io.springsecurity.springsecurity6x.security.core.mfa;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import jakarta.servlet.http.HttpServletRequest;

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
            FactorContext ctx = new FactorContext();
            ctx.sessionId(k);
            return ctx;
        });
    }

    @Override
    public void saveContext(FactorContext ctx) {
        store.put(ctx.sessionId(), ctx);
    }

    @Override
    public void delete(FactorContext ctx) {
        store.remove(ctx.sessionId());
    }
}
