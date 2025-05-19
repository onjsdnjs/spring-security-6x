package io.springsecurity.springsecurity6x.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.service.ott.EmailOneTimeTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Slf4j
@RequiredArgsConstructor // 생성자 주입을 위해
public class MfaContinuationFilter extends OncePerRequestFilter {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;
    private final ObjectMapper objectMapper;
    @Nullable
    private final EmailOneTimeTokenService emailOttService;

    private RequestMatcher requestMatcher;

    // 생성자에서 RequestMatcher 초기화
    public void MfaContinuationFilterInitializer() { // 메서드명 변경 (스프링 빈 라이프사이클과 무관하도록)
        String mfaInitiatePath = authContextProperties.getMfa().getInitiateUrl();
        Assert.hasText(mfaInitiatePath, "spring.auth.mfa.initiate-url must be configured");

        this.requestMatcher = new OrRequestMatcher(
                new AntPathRequestMatcher(mfaInitiatePath), // 예: /mfa/initiate (GET/POST 모두 처리 가정)
                new AntPathRequestMatcher("/mfa/select-factor", HttpMethod.GET.name()),
                new AntPathRequestMatcher("/api/mfa/select-factor", HttpMethod.POST.name()),
                new AntPathRequestMatcher("/mfa/challenge/**", HttpMethod.GET.name()), // 예: /mfa/challenge/ott
                new AntPathRequestMatcher("/api/mfa/resend-code", HttpMethod.POST.name())
                // Passkey Assertion Options API는 Spring Security WebAuthn 기본 엔드포인트(/webauthn/assertion/options)를
                // 클라이언트가 직접 호출하도록 유도하고, 이 필터는 그 이전 단계(챌린지 UI 안내)까지만 담당.
        );
        log.info("MfaContinuationFilter initialized. Listening for MFA continuation requests on: {}, /mfa/select-factor, /api/mfa/select-factor, /mfa/challenge/**, /api/mfa/resend-code", mfaInitiatePath);
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // RequestMatcher 초기화 (afterPropertiesSet 대용)
        if (this.requestMatcher == null) {
            MfaContinuationFilterInitializer(); // 명시적 호출
        }

        if (!this.requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("MfaContinuationFilter processing request: {} {}", request.getMethod(), request.getRequestURI());

        FactorContext ctx = contextPersistence.contextLoad(request);
        if (ctx == null || ctx.getMfaSessionId() == null) { // mfaSessionId null 체크 추가
            log.warn("MfaContinuationFilter: No valid FactorContext found for request: {}. MFA session might be missing or corrupted.", request.getRequestURI());
            responseWriter.writeErrorResponse(response, HttpStatus.UNAUTHORIZED.value(), "MFA_SESSION_INVALID", "MFA 세션이 유효하지 않습니다. 다시 로그인해주세요.", request.getRequestURI());
            return;
        }

        // 터미널 상태이거나, MFA가 정책상 필요 없는 것으로 이미 결론난 경우 더 이상 진행 안 함
        if (ctx.getCurrentMfaState() == null || ctx.getCurrentMfaState().isTerminal() || !ctx.isMfaRequiredAsPerPolicy()) {
            log.debug("MfaContinuationFilter: FactorContext for session {} is in state {} or MFA not required. Not processing further. Passing to chain.", ctx.getMfaSessionId(), ctx.getCurrentMfaState());
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String requestUri = request.getRequestURI();
            String contextPath = request.getContextPath();
            String mfaInitiateUrlConfigured = authContextProperties.getMfa().getInitiateUrl();
            String mfaInitiateUrl = StringUtils.hasText(contextPath) ? contextPath + mfaInitiateUrlConfigured : mfaInitiateUrlConfigured;


            if (requestUri.equals(mfaInitiateUrl) && ctx.getCurrentMfaState() == MfaState.PRIMARY_AUTHENTICATION_COMPLETED) {
                handleMfaInitiation(request, response, ctx);
            }
            else if (HttpMethod.GET.matches(request.getMethod()) && requestUri.equals(contextPath + "/mfa/select-factor")) {
                // 실제 View 렌더링은 LoginController에서 담당. 이 필터는 상태 검증 및 통과.
                if (ctx.getCurrentMfaState() == MfaState.AWAITING_FACTOR_SELECTION || ctx.getCurrentMfaState() == MfaState.PRIMARY_AUTHENTICATION_COMPLETED) {
                    ctx.setCurrentMfaState(MfaState.AWAITING_FACTOR_SELECTION); // 상태 명시
                    contextPersistence.saveContext(ctx, request);
                    log.info("MfaContinuationFilter: Allowing access to /mfa/select-factor page for session {}", ctx.getMfaSessionId());
                    filterChain.doFilter(request, response); // 다음 필터로 넘겨 View Controller가 처리하도록
                } else {
                    handleInvalidStateForRequest(request, response, ctx, MfaState.AWAITING_FACTOR_SELECTION);
                }
            }
            else if (HttpMethod.POST.matches(request.getMethod()) && requestUri.equals(contextPath + "/api/mfa/select-factor")) {
                handleFactorSelectionApi(request, response, ctx);
            }
            else if (HttpMethod.GET.matches(request.getMethod()) && requestUri.startsWith(contextPath + "/mfa/challenge/")) {
                handleFactorChallengeUiRequest(request, response, ctx, requestUri, filterChain);
            }
            else if (HttpMethod.POST.matches(request.getMethod()) && requestUri.equals(contextPath + "/api/mfa/resend-code")) {
                handleResendOttCodeApi(request, response, ctx);
            }
            else {
                log.warn("MfaContinuationFilter: No specific handler for matched MFA request (or state mismatch): {} {} for state {}", request.getMethod(), requestUri, ctx.getCurrentMfaState());
                filterChain.doFilter(request, response);
            }

        } catch (Exception e) {
            log.error("Error during MFA continuation processing for session {}: {}", ctx.getMfaSessionId(), e.getMessage(), e);
            if (!response.isCommitted()) {
                responseWriter.writeErrorResponse(response, HttpStatus.INTERNAL_SERVER_ERROR.value(), "MFA_PROCESSING_ERROR", "MFA 처리 중 오류가 발생했습니다.", request.getRequestURI());
            }
        }
    }

    private void handleMfaInitiation(HttpServletRequest request, HttpServletResponse response, FactorContext ctx) throws IOException {
        log.info("MfaContinuationFilter: Handling MFA initiation for session: {}", ctx.getMfaSessionId());
        Assert.state(ctx.getCurrentMfaState() == MfaState.PRIMARY_AUTHENTICATION_COMPLETED, "MFA initiation must be from PRIMARY_AUTHENTICATION_COMPLETED state.");
        Assert.state(ctx.isMfaRequiredAsPerPolicy(), "MFA must be required by policy for MFA initiation.");
        Assert.state(!CollectionUtils.isEmpty(ctx.getRegisteredMfaFactors()), "User must have registered MFA factors for MFA initiation.");

        // MfaPolicyProvider는 1차 인증 성공 핸들러에서 이미 currentProcessingFactor와 currentMfaState를 설정했을 수 있음.
        // 여기서는 해당 설정을 따르거나, 다시 한번 다음 Factor를 결정하여 안내.
        AuthType nextFactor = ctx.getCurrentProcessingFactor(); // 1차 인증 성공 핸들러에서 설정한 값 사용
        if (nextFactor == null) { // 만약 1차 인증 성공 핸들러에서 첫 Factor를 결정하지 않았다면, 여기서 다시 결정
            nextFactor = mfaPolicyProvider.determineNextFactorToProcess(ctx);
        }

        if (nextFactor != null) {
            log.info("MfaContinuationFilter: Next factor for user {} is {}. Redirecting to its challenge UI. Session: {}", ctx.getUsername(), nextFactor, ctx.getMfaSessionId());
            ctx.setCurrentProcessingFactor(nextFactor);
            ctx.setCurrentMfaState(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);
            contextPersistence.saveContext(ctx, request);
            response.sendRedirect(buildFactorChallengeUiUrl(request, nextFactor));
        } else { // 등록된 Factor는 있지만, 정책상 진행할 다음 Factor가 없는 경우 (예: 모든 Factor가 이미 완료됨)
            // 또는 사용자가 선택해야 하는 경우. 여기서는 Factor 선택으로 유도.
            log.info("MfaContinuationFilter: No specific next factor determined for user {}. Redirecting to factor selection. Session: {}", ctx.getUsername(), ctx.getMfaSessionId());
            ctx.setCurrentMfaState(MfaState.AWAITING_FACTOR_SELECTION);
            contextPersistence.saveContext(ctx, request);
            response.sendRedirect(request.getContextPath() + "/mfa/select-factor");
        }
    }

    private void handleFactorSelectionApi(HttpServletRequest request, HttpServletResponse response, FactorContext ctx) throws IOException {
        if (ctx.getCurrentMfaState() != MfaState.AWAITING_FACTOR_SELECTION) {
            handleInvalidStateForRequest(request, response, ctx, MfaState.AWAITING_FACTOR_SELECTION);
            return;
        }

        SelectFactorRequestDto selectRequest;
        try {
            selectRequest = objectMapper.readValue(request.getInputStream(), SelectFactorRequestDto.class);
        } catch (IOException e) {
            log.warn("Failed to parse SelectFactorRequestDto from request body for session {}: {}", ctx.getMfaSessionId(), e.getMessage());
            responseWriter.writeErrorResponse(response, HttpStatus.BAD_REQUEST.value(), "INVALID_REQUEST_BODY", "잘못된 요청 형식입니다.", request.getRequestURI());
            return;
        }

        String factorTypeStr = selectRequest.factorType();
        log.info("MfaContinuationFilter: Handling factor selection API. User selected: {}, Session: {}", factorTypeStr, ctx.getMfaSessionId());

        if (!StringUtils.hasText(factorTypeStr)) {
            responseWriter.writeErrorResponse(response, HttpStatus.BAD_REQUEST.value(), "FACTOR_TYPE_MISSING", "인증 수단이 선택되지 않았습니다.", request.getRequestURI());
            return;
        }

        AuthType selectedFactor;
        try {
            selectedFactor = AuthType.valueOf(factorTypeStr.toUpperCase());
        } catch (IllegalArgumentException e) {
            log.warn("Invalid factor type selected: {} for session {}", factorTypeStr, ctx.getMfaSessionId());
            responseWriter.writeErrorResponse(response, HttpStatus.BAD_REQUEST.value(), "INVALID_FACTOR_TYPE", "유효하지 않은 인증 수단입니다: " + factorTypeStr, request.getRequestURI());
            return;
        }

        if (CollectionUtils.isEmpty(ctx.getRegisteredMfaFactors()) || !ctx.getRegisteredMfaFactors().contains(selectedFactor)) {
            log.warn("User {} (session {}) selected factor {} which is not registered or available.", ctx.getUsername(), ctx.getMfaSessionId(), selectedFactor);
            responseWriter.writeErrorResponse(response, HttpStatus.FORBIDDEN.value(), "UNREGISTERED_FACTOR", "선택한 인증 수단(" + selectedFactor + ")은 사용할 수 없습니다.", request.getRequestURI());
            return;
        }

        ctx.setCurrentProcessingFactor(selectedFactor);
        ctx.setCurrentMfaState(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);
        contextPersistence.saveContext(ctx, request);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("status", "FACTOR_SELECTED_PROCEED_TO_CHALLENGE");
        responseBody.put("message", selectedFactor.name() + " 인증을 시작합니다. 해당 페이지로 이동합니다.");
        responseBody.put("nextStepUrl", buildFactorChallengeUiUrl(request, selectedFactor));
        responseBody.put("mfaSessionId", ctx.getMfaSessionId());

        responseWriter.writeSuccessResponse(response, responseBody, HttpStatus.OK.value());
    }

    private void handleFactorChallengeUiRequest(HttpServletRequest request, HttpServletResponse response, FactorContext ctx, String requestUri, FilterChain chain) throws IOException, ServletException {
        String factorTypeFromPath = requestUri.substring((request.getContextPath() + "/mfa/challenge/").length()).toUpperCase();
        AuthType requestedFactor;
        try {
            requestedFactor = AuthType.valueOf(factorTypeFromPath);
        } catch (IllegalArgumentException e) {
            log.warn("Invalid factor type in challenge UI URL: {}. Session: {}", factorTypeFromPath, ctx.getMfaSessionId());
            responseWriter.writeErrorResponse(response, HttpStatus.BAD_REQUEST.value(), "INVALID_URL_FACTOR", "잘못된 인증 수단 URL입니다.", request.getRequestURI());
            return;
        }

        log.debug("MfaContinuationFilter: Handling GET request for MFA challenge UI for factor: {}. Current context factor: {}, State: {}. Session: {}",
                requestedFactor, ctx.getCurrentProcessingFactor(), ctx.getCurrentMfaState(), ctx.getMfaSessionId());

        if (ctx.getCurrentMfaState() != MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION || ctx.getCurrentProcessingFactor() != requestedFactor) {
            log.warn("Challenge UI for factor {} requested in unexpected state ({}) or for wrong current factor (current: {}). Session: {}",
                    requestedFactor, ctx.getCurrentMfaState(), ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());
            response.sendRedirect(request.getContextPath() + "/mfa/select-factor?error=invalid_state_for_challenge_ui");
            return;
        }

        // OTT의 경우, 코드 발송 트리거 (Spring Security 엔진에 위임)
        if (requestedFactor == AuthType.OTT) {
            if (emailOttService != null) {
                try {
                    log.info("MfaContinuationFilter: Requesting OTT code generation for user {} (session {}) before rendering OTT challenge UI.", ctx.getUsername(), ctx.getMfaSessionId());
                    GenerateOneTimeTokenRequest tokenRequest = new GenerateOneTimeTokenRequest(ctx.getUsername());
                    emailOttService.generate(tokenRequest); // Spring Security의 OneTimeTokenService 호출
                } catch (Exception e) {
                    log.error("MfaContinuationFilter: Failed to generate/send OTT for user {} (session {}): {}", ctx.getUsername(), ctx.getMfaSessionId(), e.getMessage(), e);
                    response.sendRedirect(request.getContextPath() + "/mfa/select-factor?error=ott_send_failure");
                    return;
                }
            } else {
                log.error("MfaContinuationFilter: EmailOneTimeTokenService is not configured. Cannot send OTT code for session {}", ctx.getMfaSessionId());
                responseWriter.writeErrorResponse(response, HttpStatus.INTERNAL_SERVER_ERROR.value(), "OTT_SERVICE_UNAVAILABLE", "OTT 서비스가 설정되지 않았습니다.", request.getRequestURI());
                return;
            }
        }
        // Passkey의 경우, 이 UI 페이지의 JS가 `/webauthn/assertion/options` (Spring Security 기본 엔드포인트) 또는
        // 플랫폼의 커스텀 API (예: `/api/mfa/passkey/options`)를 호출하여 Assertion Options를 받아야 함.
        // 이 필터는 해당 UI 페이지로의 접근을 허용하고 상태를 변경하는 역할.

        ctx.setCurrentMfaState(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
        contextPersistence.saveContext(ctx, request);
        log.info("MfaContinuationFilter: Proceeding to render challenge UI for factor {} (session {})", requestedFactor, ctx.getMfaSessionId());
        chain.doFilter(request, response); // 다음 필터로 넘겨 View Controller가 실제 UI 페이지 렌더링
    }

    private void handleResendOttCodeApi(HttpServletRequest request, HttpServletResponse response, FactorContext ctx) throws IOException {
        log.debug("MfaContinuationFilter: Handling OTT code resend request for session: {}", ctx.getMfaSessionId());

        // 상태 및 현재 처리 중인 Factor 타입 검증
        if (ctx.getCurrentMfaState() != MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ||
                ctx.getCurrentProcessingFactor() != AuthType.OTT) {
            log.warn("OTT code resend requested in an invalid state ({}) or for non-OTT factor ({}). Session: {}",
                    ctx.getCurrentMfaState(), ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());
            responseWriter.writeErrorResponse(response, HttpStatus.BAD_REQUEST.value(), "INVALID_STATE_FOR_OTT_RESEND", "잘못된 상태에서 OTT 코드 재전송을 요청했습니다.", request.getRequestURI());
            return;
        }

        if (emailOttService != null) {
            try {
                log.info("MfaContinuationFilter: Resending OTT code for user {} (session {})", ctx.getUsername(), ctx.getMfaSessionId());
                GenerateOneTimeTokenRequest tokenRequest = new GenerateOneTimeTokenRequest(ctx.getUsername());
                emailOttService.generate(tokenRequest); // Spring Security의 OneTimeTokenService 호출
                responseWriter.writeSuccessResponse(response, Map.of("message", "인증 코드가 재전송되었습니다."), HttpStatus.OK.value());
            } catch (Exception e) {
                log.error("MfaContinuationFilter: Failed to resend OTT for user {} (session {}): {}", ctx.getUsername(), ctx.getMfaSessionId(), e.getMessage(), e);
                responseWriter.writeErrorResponse(response, HttpStatus.INTERNAL_SERVER_ERROR.value(), "OTT_RESEND_FAILED", "코드 재전송에 실패했습니다.", request.getRequestURI());
            }
        } else {
            log.error("MfaContinuationFilter: EmailOneTimeTokenService is not configured. Cannot resend OTT code for session {}", ctx.getMfaSessionId());
            responseWriter.writeErrorResponse(response, HttpStatus.INTERNAL_SERVER_ERROR.value(), "OTT_SERVICE_UNAVAILABLE", "OTT 서비스가 설정되지 않았습니다.", request.getRequestURI());
        }
    }

    private void handleInvalidStateForRequest(HttpServletRequest request, HttpServletResponse response, FactorContext ctx, MfaState expectedState) throws IOException {
        log.warn("MfaContinuationFilter: Request to {} made in an unexpected MFA state: {}. Expected around: {}. Session: {}",
                request.getRequestURI(), ctx.getCurrentMfaState(), expectedState, ctx.getMfaSessionId());
        responseWriter.writeErrorResponse(response, HttpStatus.CONFLICT.value(), "INVALID_MFA_STATE", "잘못된 MFA 진행 상태입니다. 처음부터 다시 시도해주세요.", request.getRequestURI());
    }

    private String buildFactorChallengeUiUrl(HttpServletRequest request, AuthType factorType) {
        String contextPath = request.getContextPath();
        return switch (factorType) {
            case OTT -> contextPath + "/mfa/challenge/ott";
            case PASSKEY -> contextPath + "/mfa/challenge/passkey";
            case RECOVERY_CODE -> contextPath + "/mfa/challenge/recovery";
            default -> {
                log.warn("MfaContinuationFilter: Unknown factor type {} for challenge UI URL generation. Defaulting to select-factor.", factorType);
                yield contextPath + "/mfa/select-factor";
            }
        };
    }

    // 요청 본문 파싱을 위한 DTO (선택적, ObjectMapper 직접 사용 가능)
    private record SelectFactorRequestDto(String factorType, String username) {}
}


