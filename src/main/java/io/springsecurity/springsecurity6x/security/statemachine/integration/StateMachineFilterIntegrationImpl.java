package io.springsecurity.springsecurity6x.security.statemachine.integration;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.core.MfaStateMachineService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * MfaContinuationFilter와 State Machine을 통합하는 구현체
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class StateMachineFilterIntegrationImpl implements StateMachineFilterIntegration {

    private final MfaStateMachineService stateMachineService;

    @Override
    public boolean preProcess(HttpServletRequest request, HttpServletResponse response, FactorContext context) {
        if (context == null || context.getMfaSessionId() == null) {
            log.warn("No valid FactorContext for State Machine pre-processing");
            return true; // 기존 로직 계속 진행
        }

        try {
            // State Machine이 초기화되어 있는지 확인
            if (stateMachineService.getCurrentState(context.getMfaSessionId()) == null) {
                log.info("Initializing State Machine for session: {}", context.getMfaSessionId());
                stateMachineService.initializeStateMachine(context.getMfaSessionId(), context);
            }

            // 현재 상태 로깅
            log.debug("Current State Machine state for session {}: {}",
                    context.getMfaSessionId(),
                    stateMachineService.getCurrentState(context.getMfaSessionId()));

            return true;

        } catch (Exception e) {
            log.error("Error in State Machine pre-processing: {}", e.getMessage(), e);
            return true; // 오류 시에도 기존 로직 계속 진행
        }
    }

    @Override
    public void postProcess(HttpServletRequest request, HttpServletResponse response,
                            FactorContext context, Object result) {
        if (context == null || context.getMfaSessionId() == null) {
            return;
        }

        try {
            // 요청 처리 결과에 따라 적절한 이벤트 발생
            MfaEvent event = determineEventFromResult(request, result);

            if (event != null) {
                log.info("Triggering State Machine event {} for session {}",
                        event, context.getMfaSessionId());

                stateMachineService.sendEvent(context.getMfaSessionId(), event, context);
            }

        } catch (Exception e) {
            log.error("Error in State Machine post-processing: {}", e.getMessage(), e);
        }
    }

    /**
     * 요청 처리 결과로부터 적절한 MfaEvent 결정
     */
    private MfaEvent determineEventFromResult(HttpServletRequest request, Object result) {
        String requestUri = request.getRequestURI();
        String method = request.getMethod();

        // Factor 선택 요청
        if (requestUri.contains("/mfa/select-factor") && "POST".equals(method)) {
            String selectedFactor = request.getParameter("factor");
            if ("OTT".equalsIgnoreCase(selectedFactor)) {
                return MfaEvent.FACTOR_SELECTED_OTT;
            } else if ("PASSKEY".equalsIgnoreCase(selectedFactor)) {
                return MfaEvent.FACTOR_SELECTED_PASSKEY;
            }
        }

        // Challenge 시작 요청
        if (requestUri.contains("/mfa/ott/generate") && "POST".equals(method)) {
            return MfaEvent.INITIATE_CHALLENGE;
        }

        // 검증 요청
        if (requestUri.contains("/login/mfa-ott") && "POST".equals(method)) {
            if (result instanceof Boolean && (Boolean) result) {
                return MfaEvent.FACTOR_VERIFIED_SUCCESS;
            } else {
                return MfaEvent.FACTOR_VERIFICATION_FAILED;
            }
        }

        return null;
    }
}
