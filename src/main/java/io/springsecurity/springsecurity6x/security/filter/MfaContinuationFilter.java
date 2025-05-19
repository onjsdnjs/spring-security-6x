package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.service.ott.EmailOneTimeTokenService; // OTT 코드 발송 요청용
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest; // 스프링 시큐리티 클래스
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;

@Slf4j
public class MfaContinuationFilter extends OncePerRequestFilter {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter; // JSON 응답 필요 시

    @Nullable // EmailOneTimeTokenService는 OTT Factor 사용 시에만 필요
    private final EmailOneTimeTokenService emailOttService;

    private final RequestMatcher requestMatcher;

    public MfaContinuationFilter(ContextPersistence contextPersistence,
                                 MfaPolicyProvider mfaPolicyProvider,
                                 AuthContextProperties authContextProperties,
                                 AuthResponseWriter responseWriter,
                                 @Nullable EmailOneTimeTokenService emailOttService) {
        this.contextPersistence = Objects.requireNonNull(contextPersistence);
        this.mfaPolicyProvider = Objects.requireNonNull(mfaPolicyProvider);
        this.authContextProperties = Objects.requireNonNull(authContextProperties);
        this.responseWriter = Objects.requireNonNull(responseWriter);
        this.emailOttService = emailOttService; // null일 수 있음

        String mfaInitiatePath = authContextProperties.getMfa().getInitiateUrl();
        Assert.hasText(mfaInitiatePath, "spring.auth.mfa.initiate-url must be configured");

        // 이 필터가 처리할 MFA UI 흐름 관련 GET 요청들
        this.requestMatcher = new OrRequestMatcher(
                new AntPathRequestMatcher(mfaInitiatePath), // 예: /mfa/initiate (1차 인증 후 MFA 시작 지점)
                new AntPathRequestMatcher("/mfa/select-factor", HttpMethod.GET.name()),
                new AntPathRequestMatcher("/mfa/challenge/**", HttpMethod.GET.name()) // 예: /mfa/challenge/ott, /mfa/challenge/passkey
                // API 요청(POST /api/mfa/select-factor 등)은 MfaApiController에서 처리
        );
        log.info("MfaContinuationFilter initialized. Listening for MFA UI flow requests on: {}, /mfa/select-factor, /mfa/challenge/**", mfaInitiatePath);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!this.requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("MfaContinuationFilter processing GET request: {}", request.getRequestURI());

        FactorContext ctx = contextPersistence.contextLoad(request);

        if (ctx == null || ctx.getMfaSessionId() == null) {
            log.warn("MfaContinuationFilter: No valid FactorContext found for request: {}. Redirecting to login.", request.getRequestURI());
            response.sendRedirect(request.getContextPath() + "/loginForm?error=mfa_session_missing");
            return;
        }

        if (ctx.getCurrentState() == null || ctx.getCurrentState().isTerminal()) {
            log.debug("MfaContinuationFilter: FactorContext for session {} is in terminal state {} or state is null. Clearing context and redirecting to login.",
                    ctx.getMfaSessionId(), ctx.getCurrentState());
            contextPersistence.deleteContext(request);
            response.sendRedirect(request.getContextPath() + "/loginForm?error=mfa_session_terminated");
            return;
        }

        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        String mfaInitiateUrlConfigured = authContextProperties.getMfa().getInitiateUrl();
        String mfaInitiateFullUrl = contextPath + mfaInitiateUrlConfigured;
        String selectFactorFullUiUrl = contextPath + "/mfa/select-factor";
        String challengeUiBaseFullUrl = contextPath + "/mfa/challenge/";

        try {
            // 1. MFA 시작 요청 처리 (예: /mfa/initiate)
            if (requestUri.equals(mfaInitiateFullUrl)) {
                if (ctx.getCurrentState() == MfaState.PRIMARY_AUTHENTICATION_COMPLETED && ctx.isMfaRequiredAsPerPolicy()) {
                    handleMfaInitiation(request, response, ctx);
                } else {
                    // 1차 인증이 완료되지 않았거나, MFA가 필요 없는 경우 등 부적절한 상태
                    log.warn("MfaContinuationFilter: Invalid state ({}) or MFA not required for MFA initiation request. Session: {}", ctx.getCurrentState(), ctx.getMfaSessionId());
                    response.sendRedirect(contextPath + "/loginForm?error=invalid_mfa_initiation_state");
                }
                return; // 응답 처리 완료
            }

            // 2. 인증 수단 선택 UI 페이지 요청 처리 (/mfa/select-factor)
            else if (requestUri.equals(selectFactorFullUiUrl)) {
                // AWAITING_FACTOR_SELECTION 상태이거나, 1차 인증 완료 후 바로 선택으로 넘어온 경우
                if (ctx.getCurrentState() == MfaState.AWAITING_FACTOR_SELECTION ||
                        (ctx.getCurrentState() == MfaState.PRIMARY_AUTHENTICATION_COMPLETED && ctx.isMfaRequiredAsPerPolicy())) {
                    ctx.changeState(MfaState.AWAITING_FACTOR_SELECTION); // 상태 명시
                    contextPersistence.saveContext(ctx, request);
                    log.info("MfaContinuationFilter: Allowing access to /mfa/select-factor page. Session: {}", ctx.getMfaSessionId());
                    filterChain.doFilter(request, response); // LoginController가 UI 렌더링
                } else {
                    log.warn("MfaContinuationFilter: Invalid state ({}) for accessing /mfa/select-factor. Session: {}", ctx.getCurrentState(), ctx.getMfaSessionId());
                    response.sendRedirect(contextPath + "/loginForm?error=invalid_state_for_factor_selection");
                }
                return;
            }

            // 3. 특정 Factor의 챌린지 UI 페이지 요청 처리 (예: /mfa/challenge/ott)
            else if (requestUri.startsWith(challengeUiBaseFullUrl)) {
                handleFactorChallengeUiRequest(request, response, ctx, requestUri, challengeUiBaseFullUrl, filterChain);
                return;
            }

            // 이 필터가 처리하지 않는 기타 MFA 관련 GET 요청은 다음 필터로
            filterChain.doFilter(request, response);

        } catch (Exception e) {
            log.error("Error during MFA continuation processing for session {}: {}", ctx.getMfaSessionId(), e.getMessage(), e);
            if (!response.isCommitted()) {
                // 보다 사용자 친화적인 오류 페이지로 리다이렉트
                String mfaFailurePage = contextPath + authContextProperties.getMfa().getFailureUrl();
                response.sendRedirect(mfaFailurePage + "?error=" + "mfa_flow_exception_occurred");
            }
        }
    }

    // 1차 인증 성공 후, 어떤 MFA Factor로 진행할지 결정하고 안내
    private void handleMfaInitiation(HttpServletRequest request, HttpServletResponse response, FactorContext ctx) throws IOException {
        log.info("MfaContinuationFilter: Handling MFA initiation. User: {}, Session: {}", ctx.getUsername(), ctx.getMfaSessionId());
        Assert.state(ctx.getCurrentState() == MfaState.PRIMARY_AUTHENTICATION_COMPLETED, "MFA initiation requires PRIMARY_AUTHENTICATION_COMPLETED state.");
        Assert.state(ctx.isMfaRequiredAsPerPolicy(), "MFA must be required by policy for initiation.");

        AuthType nextFactor = ctx.getCurrentProcessingFactor(); // 1차 인증 핸들러에서 이미 설정했을 수 있음
        if (nextFactor == null) { // 설정 안됐으면 여기서 결정
            nextFactor = mfaPolicyProvider.determineNextFactorToProcess(ctx);
            ctx.setCurrentProcessingFactor(nextFactor);
        }

        if (nextFactor != null) {
            log.info("MfaContinuationFilter: Next factor determined: {}. Redirecting to its challenge UI. User: {}, Session: {}", nextFactor, ctx.getUsername(), ctx.getMfaSessionId());
            ctx.changeState(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION); // 다음 상태: 이 Factor의 챌린지 시작 대기
            contextPersistence.saveContext(ctx, request);
            response.sendRedirect(request.getContextPath() + "/mfa/challenge/" + nextFactor.name().toLowerCase());
        } else {
            // 등록된 Factor는 있지만, 정책상 진행할 다음 Factor가 없는 경우 (예: 모든 Factor가 이미 완료됨)
            // 또는 사용자가 직접 선택해야 하는 경우. 여기서는 Factor 선택으로 유도.
            log.info("MfaContinuationFilter: No specific next factor determined. Redirecting to factor selection. User: {}, Session: {}", ctx.getUsername(), ctx.getMfaSessionId());
            ctx.changeState(MfaState.AWAITING_FACTOR_SELECTION);
            contextPersistence.saveContext(ctx, request);
            response.sendRedirect(request.getContextPath() + "/mfa/select-factor");
        }
    }

    // 특정 Factor의 챌린지 UI 페이지 요청 처리
    private void handleFactorChallengeUiRequest(HttpServletRequest request, HttpServletResponse response, FactorContext ctx, String requestUri, String challengeUiBaseFullUrl, FilterChain filterChain) throws IOException, ServletException {
        String factorTypeSegment = requestUri.substring(challengeUiBaseFullUrl.length());
        AuthType requestedFactor;
        try {
            requestedFactor = AuthType.valueOf(factorTypeSegment.toUpperCase());
        } catch (IllegalArgumentException e) {
            log.warn("Invalid factor type in challenge UI URL: {}. Session: {}", factorTypeSegment, ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + "/mfa/select-factor?error=invalid_factor_url");
            return;
        }

        log.debug("MfaContinuationFilter: Handling GET request for MFA challenge UI for factor: {}. Current context factor: {}, State: {}. Session: {}",
                requestedFactor, ctx.getCurrentProcessingFactor(), ctx.getCurrentState(), ctx.getMfaSessionId());

        // 상태 및 현재 처리해야 할 Factor가 일치하는지 확인
        if (ctx.getCurrentState() != MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION ||
                ctx.getCurrentProcessingFactor() != requestedFactor) {
            log.warn("Challenge UI for factor {} requested in unexpected state ({}) or for wrong current factor (current: {}). Session: {}",
                    requestedFactor, ctx.getCurrentState(), ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + "/mfa/select-factor?error=state_mismatch_for_challenge_ui");
            return;
        }

        // OTT 챌린지 UI 로드 전, 스프링 시큐리티의 OneTimeTokenService를 호출하여 코드 생성 및 발송 "요청"
        if (requestedFactor == AuthType.OTT) {
            if (emailOttService != null) {
                try {
                    emailOttService.generate(new GenerateOneTimeTokenRequest(ctx.getUsername()));
                    log.info("MFA OTT code generation requested via EmailOneTimeTokenService for user {} (session {}) before rendering OTT challenge UI.", ctx.getUsername(), ctx.getMfaSessionId());
                } catch (Exception e) {
                    log.error("MfaContinuationFilter: Failed to request OTT code generation for user {} (session {}): {}", ctx.getUsername(), ctx.getMfaSessionId(), e.getMessage(), e);
                    response.sendRedirect(request.getContextPath() + "/mfa/select-factor?error=ott_send_failure");
                    return;
                }
            } else { // emailOttService가 설정되지 않은 경우 (치명적 설정 오류)
                log.error("EmailOneTimeTokenService is null. Cannot request OTT code generation for MFA. Session: {}", ctx.getMfaSessionId());
                responseWriter.writeErrorResponse(response, HttpStatus.INTERNAL_SERVER_ERROR.value(), "OTT_SERVICE_UNCONFIGURED", "OTT 서비스가 설정되지 않았습니다.", request.getRequestURI());
                return;
            }
        }
        // Passkey 챌린지 UI 로드 시, 클라이언트 측 JS가 서버의 Passkey Assertion Options API (예: /api/mfa/assertion/options)를 호출하도록 유도.
        // 이 필터는 해당 UI 페이지로의 접근을 허용하고, 상태를 변경.

        ctx.changeState(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION); // 다음 상태: 이 Factor에 대한 검증 대기
        contextPersistence.saveContext(ctx, request);
        log.info("MfaContinuationFilter: Proceeding to render challenge UI for factor {} (session {}). New state: {}",
                requestedFactor, ctx.getMfaSessionId(), ctx.getCurrentState());
        filterChain.doFilter(request, response); // LoginController가 실제 UI 페이지 렌더링
    }
}


