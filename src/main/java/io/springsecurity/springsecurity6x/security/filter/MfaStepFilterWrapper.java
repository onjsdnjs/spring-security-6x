package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

@Slf4j
public class MfaStepFilterWrapper extends OncePerRequestFilter {

    private static final String ATTR_FACTOR_ID = "currentFactorId"; // 속성명 변경 고려

    private final FeatureRegistry featureRegistry;
    private final ContextPersistence ctxPersistence;
    private final RequestMatcher requestMatcher = new OrRequestMatcher(
            new AntPathRequestMatcher("/api/auth/login", "POST"), // 1차 인증
            new AntPathRequestMatcher("/login/ott", "POST"),      // OTT 제출
            new AntPathRequestMatcher("/login/webauthn", "POST"), // Passkey 제출
            new AntPathRequestMatcher("/api/auth/mfa", "POST")    // MFA 다음 단계 처리 등
    );

    public MfaStepFilterWrapper(FeatureRegistry featureRegistry, ContextPersistence ctxPersistence) {
        this.featureRegistry = Objects.requireNonNull(featureRegistry, "featureRegistry cannot be null");
        this.ctxPersistence  = Objects.requireNonNull(ctxPersistence, "ctxPersistence cannot be null");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        if (!requestMatcher.matches(req)) {
            chain.doFilter(req, res);
            return;
        }

        FactorContext ctx = ctxPersistence.contextLoad(req);
        if (ctx == null) {
            // OrchestrationFilter 에서 이미 처리했어야 하지만, 방어적으로 추가
            log.warn("MfaStepFilterWrapper: FactorContext is null. Proceeding with chain.");
            chain.doFilter(req, res);
            return;
        }
        MfaState currentState = ctx.getCurrentState();


        if (currentState == null || currentState.isTerminal()) { // MfaState.isTerminal() 사용
            chain.doFilter(req, res);
            return;
        }

        // FactorContext 에서 현재 처리 중인 Factor 타입을 직접 가져옴
        AuthType currentFactorType = ctx.getCurrentProcessingFactor();

        if (currentFactorType != null) {
            String factorId = currentFactorType.name().toLowerCase(); // 예: AuthType.OTT -> "ott"
            Filter delegate = featureRegistry.getFactorFilter(factorId);

            if (delegate != null) {
                log.debug("Delegating to factor filter: {} for state: {} and factor type: {}", delegate.getClass().getSimpleName(), currentState, currentFactorType);
                req.setAttribute(ATTR_FACTOR_ID, factorId); // 필요하다면 factorId 전달
                delegate.doFilter(req, res, chain);
                // 인증 필터(AbstractAuthenticationProcessingFilter 등)는 일반적으로 성공/실패 시
                // 응답을 직접 처리(redirect 또는 응답 작성)하고 필터 체인을 더 이상 진행시키지 않거나,
                // continueChain을 명시적으로 호출하지 않으므로 여기서 return이 적절할 수 있음.
                // 만약 delegate 필터가 응답을 커밋하지 않고 다음 필터로 넘겨야 한다면,
                // 여기서 return을 제거하고 chain.doFilter를 호출해야 함.
                // 현재 설계에서는 Factor 인증 필터가 요청을 완전히 처리한다고 가정.
                return;
            } else {
                log.warn("No delegate filter found for factorId: {} (derived from factor type: {})", factorId, currentFactorType);
            }
        } else {
            log.debug("No current processing factor set in FactorContext for state: {}", currentState);
        }

        chain.doFilter(req, res);
    }
}


