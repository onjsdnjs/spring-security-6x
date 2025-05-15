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

    private static final String ATTR_CURRENT_PROCESSING_FACTOR_TYPE = "currentProcessingFactorType"; // 속성명 변경

    private final FeatureRegistry featureRegistry;
    private final ContextPersistence ctxPersistence;

    // 이 필터는 특정 Factor에 대한 실제 인증 처리가 필요한 요청(예: Factor 검증 URL)을 처리해야 함.
    // RequestMatcher는 이를 반영해야 함.
    private final RequestMatcher requestMatcher;

    public MfaStepFilterWrapper(FeatureRegistry featureRegistry,
                                ContextPersistence ctxPersistence,
                                RequestMatcher factorProcessingRequestMatcher) {
        this.featureRegistry = Objects.requireNonNull(featureRegistry, "featureRegistry cannot be null");
        this.ctxPersistence  = Objects.requireNonNull(ctxPersistence, "ctxPersistence cannot be null");
        this.requestMatcher = Objects.requireNonNull(factorProcessingRequestMatcher, "factorProcessingRequestMatcher cannot be null");
        log.info("MfaStepFilterWrapper initialized with provided request matcher.");
    }
    // 업로드된 코드의 기존 생성자 유지 (기본 Matcher 제공)
    public MfaStepFilterWrapper(FeatureRegistry featureRegistry, ContextPersistence ctxPersistence) {
        this.featureRegistry = Objects.requireNonNull(featureRegistry, "featureRegistry cannot be null");
        this.ctxPersistence  = Objects.requireNonNull(ctxPersistence, "ctxPersistence cannot be null");
        // 이 기본 Matcher는 각 Factor의 구체적인 처리 URL을 포함하도록 수정되어야 합니다.
        // 예를 들어, 각 Factor의 DSL 에서 정의된 processingUrl을 기반으로 동적으로 구성될 수 있습니다.
        // 현재는 이전 버전의 URL 들을 포함하고 있으므로, 새로운 MFA 흐름에 맞게 조정이 필요합니다.
        this.requestMatcher = new OrRequestMatcher(
                // new AntPathRequestMatcher("/api/auth/login", "POST"), // 1차 인증은 이 필터의 역할이 아님
                new AntPathRequestMatcher("/api/mfa/verify/**", "POST") // 예: /api/mfa/verify/passkey, /api/mfa/verify/ott
                // 이전: new AntPathRequestMatcher("/login/ott", "POST"),
                // 이전: new AntPathRequestMatcher("/login/webauthn", "POST"),
                // 이전: new AntPathRequestMatcher("/api/auth/mfa", "POST")
        );
        log.info("MfaStepFilterWrapper initialized with default request matchers. This likely needs to be more specific for production.");
    }


    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        if (!requestMatcher.matches(req)) {
            chain.doFilter(req, res);
            return;
        }

        log.debug("MfaStepFilterWrapper processing request: {} {}", req.getMethod(), req.getRequestURI());

        FactorContext ctx = ctxPersistence.contextLoad(req);
        if (ctx == null) {
            log.warn("MfaStepFilterWrapper: FactorContext is null for request: {}. This should ideally be handled by MfaOrchestrationFilter or earlier.", req.getRequestURI());
            // 오류 응답을 보내거나, 다음 체인으로 넘겨 다른 필터가 처리하도록 할 수 있음.
            // MfaOrchestrationFilter 에서 이미 컨텍스트 로드 실패를 처리했을 가능성이 높음.
            chain.doFilter(req, res); // 또는 오류 응답
            return;
        }

        MfaState currentState = ctx.getCurrentState();
        log.debug("Current MFA State: {}, Session ID: {}", currentState, ctx.getMfaSessionId());

        // MfaState enum에 isTerminal() 메소드가 정의되어 있다고 가정
        if (currentState == null || currentState.isTerminal()) {
            log.debug("MFA state for session {} is null or terminal ({}). MfaStepFilterWrapper will not delegate.", ctx.getMfaSessionId(), currentState);
            chain.doFilter(req, res);
            return;
        }

        // FactorContext 에서 현재 처리 중인 Factor 타입을 직접 가져옴
        AuthType currentFactorType = ctx.getCurrentProcessingFactor();

        if (currentFactorType != null &&
                (currentState == MfaState.FACTOR_CHALLENGE_INITIATED || // 챌린지 후 사용자 입력 제출 시
                        currentState == MfaState.FACTOR_VERIFICATION_PENDING || // 실제 검증 로직 실행 시
                        currentState == MfaState.AUTO_ATTEMPT_FACTOR_VERIFICATION_PENDING) // 자동 시도 검증 로직 실행 시
        ) {
            String factorId = currentFactorType.name().toLowerCase(); // 예: AuthType.OTT -> "ott"
            Filter delegate = featureRegistry.getFactorFilter(factorId);

            if (delegate != null) {
                log.debug("Delegating to factor filter: {} for state: {} and factor type: {} (Session: {})",
                        delegate.getClass().getSimpleName(), currentState, currentFactorType, ctx.getMfaSessionId());
                // 필요하다면 요청 속성에 현재 처리 중인 Factor 정보를 설정
                req.setAttribute(ATTR_CURRENT_PROCESSING_FACTOR_TYPE, currentFactorType);
                delegate.doFilter(req, res, chain);
                // 대부분의 Spring Security 인증 필터는 요청 처리를 완료하고 응답을 커밋하므로,
                // 여기서 return 하여 다음 필터 체인 실행을 막는 것이 일반적입니다.
                // 만약 delegate 필터가 응답을 커밋하지 않고 다음 필터로 넘겨야 하는 특별한 경우가 있다면,
                // 아래 return 문을 제거하고 chain.doFilter(req,res)를 호출해야 합니다.
                return;
            } else {
                log.warn("No delegate filter found in FeatureRegistry for factorId: '{}' (derived from factor type: {}) for session {}. Proceeding with chain.",
                        factorId, currentFactorType, ctx.getMfaSessionId());
            }
        } else {
            log.debug("No current processing factor set in FactorContext, or current state ({}) is not suitable for factor filter delegation for session {}. Proceeding with chain.",
                    currentState, ctx.getMfaSessionId());
        }

        chain.doFilter(req, res);
    }
}


