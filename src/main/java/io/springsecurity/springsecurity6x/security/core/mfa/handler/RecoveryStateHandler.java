package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.HashMap;
import java.util.Map;

/**
 * MFA 복구 흐름 안내 핸들러
 */
public class RecoveryStateHandler implements MfaStateHandler {
    private final ContextPersistence ctxPersistence;
    private final ObjectMapper mapper = new ObjectMapper();

    public RecoveryStateHandler(ContextPersistence ctxPersistence) {
        this.ctxPersistence = ctxPersistence;
    }

    @Override
    public boolean supports(MfaState state) {
        return state == MfaState.RECOVERY;
    }

    @Override
    public void handle(FactorContext ctx, HttpServletRequest req, HttpServletResponse res) throws Exception {
        // 복구 URL 안내
        var recovery = ctx.getRecoveryConfig();
        String url = recovery != null ? recovery.getEmailOtpEndpoint() : null;

        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/json");
        Map<String,Object> body = new HashMap<>();
        body.put("sessionId", ctx.getSessionId());
        body.put("state", ctx.getCurrentState().name());
        if (url != null) {
            body.put("recoverUrl", url);
        }
        mapper.writeValue(res.getWriter(), body);
    }
}
