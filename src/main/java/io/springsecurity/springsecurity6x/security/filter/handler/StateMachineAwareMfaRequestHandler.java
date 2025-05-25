package io.springsecurity.springsecurity6x.security.filter.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.filter.matcher.MfaRequestType;
import io.springsecurity.springsecurity6x.security.filter.matcher.MfaUrlMatcher;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;

import java.io.IOException;

@Slf4j
public class StateMachineAwareMfaRequestHandler extends MfaRequestHandler {

    private final MfaStateMachineIntegrator stateMachineIntegrator;

    public StateMachineAwareMfaRequestHandler(ContextPersistence contextPersistence,
                                              MfaPolicyProvider mfaPolicyProvider,
                                              AuthContextProperties authContextProperties,
                                              AuthResponseWriter responseWriter,
                                              ApplicationContext applicationContext,
                                              MfaUrlMatcher urlMatcher,
                                              MfaStateMachineIntegrator stateMachineIntegrator) {
        super(contextPersistence, mfaPolicyProvider, authContextProperties,
                responseWriter, applicationContext, urlMatcher);
        this.stateMachineIntegrator = stateMachineIntegrator;
    }

    @Override
    public void handleRequest(MfaRequestType requestType, HttpServletRequest request,
                              HttpServletResponse response, FactorContext ctx,
                              FilterChain filterChain) throws IOException, ServletException {

        log.debug("Processing {} request with State Machine for session: {} in state: {}",
                requestType, ctx.getMfaSessionId(), ctx.getCurrentState());

        switch (requestType) {
            case MFA_INITIATE:
                handleMfaInitiateWithStateMachine(request, response, ctx);
                break;

            case SELECT_FACTOR:
                handleSelectFactorWithStateMachine(request, response, ctx);
                break;

            case TOKEN_GENERATION:
                handleTokenGenerationWithStateMachine(request, response, ctx, filterChain);
                break;

            case LOGIN_PROCESSING:
                // OTT 검증 등의 실제 인증 처리
                handleLoginProcessingWithStateMachine(request, response, ctx, filterChain);
                break;

            default:
                super.handleRequest(requestType, request, response, ctx, filterChain);
        }
    }

    private void handleMfaInitiateWithStateMachine(HttpServletRequest request,
                                                   HttpServletResponse response,
                                                   FactorContext ctx) throws IOException {
        MfaState currentState = ctx.getCurrentState();

        // 필요한 경우 State Machine 이벤트 전송
        if (currentState == MfaState.PRIMARY_AUTHENTICATION_COMPLETED) {
            boolean accepted = stateMachineIntegrator.sendEvent(
                    MfaEvent.MFA_REQUIRED_SELECT_FACTOR, ctx, request);

            if (!accepted) {
                handleInvalidStateTransition(request, response, ctx,
                        MfaEvent.MFA_REQUIRED_SELECT_FACTOR);
                return;
            }
        }

        // 기존 로직 실행
        super.handleMfaInitiate(request, response, ctx);
    }

    private void handleSelectFactorWithStateMachine(HttpServletRequest request,
                                                    HttpServletResponse response,
                                                    FactorContext ctx) throws IOException {
        if (!"POST".equals(request.getMethod())) {
            // GET 요청은 페이지 렌더링
            return;
        }

        String selectedFactor = request.getParameter("factor");
        if (selectedFactor == null) {
            getResponseWriter().writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "FACTOR_NOT_SPECIFIED", "인증 수단이 지정되지 않았습니다.",
                    request.getRequestURI(), null);
            return;
        }

        try {
            AuthType authType = AuthType.valueOf(selectedFactor.toUpperCase());
            ctx.setCurrentProcessingFactor(authType);

            // FACTOR_SELECTED 이벤트 전송
            boolean accepted = stateMachineIntegrator.sendEvent(
                    MfaEvent.FACTOR_SELECTED, ctx, request);

            if (accepted) {
                // 다음 단계 결정
                getMfaPolicyProvider().determineNextFactorToProcess(ctx);
                getContextPersistence().saveContext(ctx, request);

                // 챌린지 URL로 리다이렉트
                String challengeUrl = determineChalllengeUrl(ctx, request);
                response.sendRedirect(challengeUrl);
            } else {
                handleInvalidStateTransition(request, response, ctx, MfaEvent.FACTOR_SELECTED);
            }
        } catch (IllegalArgumentException e) {
            getResponseWriter().writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "INVALID_FACTOR", "잘못된 인증 수단: " + selectedFactor,
                    request.getRequestURI(), null);
        }
    }

    private void handleTokenGenerationWithStateMachine(HttpServletRequest request,
                                                       HttpServletResponse response,
                                                       FactorContext ctx,
                                                       FilterChain filterChain)
            throws IOException, ServletException {

        // State Machine 상태 확인
        if (ctx.getCurrentState() != MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION &&
                ctx.getCurrentState() != MfaState.FACTOR_CHALLENGE_INITIATED) {
            log.warn("Invalid state {} for token generation", ctx.getCurrentState());
            handleInvalidState(request, response, ctx);
            return;
        }

        // INITIATE_CHALLENGE 이벤트 전송
        boolean accepted = stateMachineIntegrator.sendEvent(
                MfaEvent.INITIATE_CHALLENGE, ctx, request);

        if (accepted) {
            // GenerateOneTimeTokenFilter로 위임
            filterChain.doFilter(request, response);
        } else {
            handleInvalidStateTransition(request, response, ctx, MfaEvent.INITIATE_CHALLENGE);
        }
    }

    private void handleLoginProcessingWithStateMachine(HttpServletRequest request,
                                                       HttpServletResponse response,
                                                       FactorContext ctx,
                                                       FilterChain filterChain)
            throws IOException, ServletException {

        // State Machine 상태 확인
        if (ctx.getCurrentState() != MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION) {
            log.warn("Invalid state {} for login processing", ctx.getCurrentState());
            handleInvalidState(request, response, ctx);
            return;
        }

        // MfaStepFilterWrapper로 위임 (SUBMIT_FACTOR_CREDENTIAL 이벤트는 거기서 처리)
        filterChain.doFilter(request, response);
    }
}
