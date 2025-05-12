package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 토큰 발급 단계 처리 핸들러
 */
public class TokenStateHandler implements MfaStateHandler {
    private final ContextPersistence ctxPersistence;
    private final TokenService tokenService;
    private final ObjectMapper mapper = new ObjectMapper();

    public TokenStateHandler(ContextPersistence ctxPersistence,
                             TokenService tokenService) {
        this.ctxPersistence = ctxPersistence;
        this.tokenService   = tokenService;
    }

    @Override
    public boolean supports(MfaState state) {
        return state == MfaState.TOKEN_ISSUANCE;
    }

    @Override
    public void handle(FactorContext ctx,
                       HttpServletRequest req,
                       HttpServletResponse res) throws Exception {
        // 토큰 생성
        var tokens = tokenService.issueTokens(ctx.getSuccesses());
        // 컨텍스트 삭제
        ctxPersistence.delete(ctx);

        // JSON 응답
        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/json");
        Map<String,Object> body = new HashMap<>();
        body.put("accessToken", tokens.getAccessToken());
        body.put("refreshToken", tokens.getRefreshToken());
        mapper.writeValue(res.getWriter(), body);
    }
}
