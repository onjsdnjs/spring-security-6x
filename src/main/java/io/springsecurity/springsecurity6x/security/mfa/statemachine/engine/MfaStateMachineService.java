package io.springsecurity.springsecurity6x.security.mfa.statemachine.engine;


import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaEventPayload;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaFlowEvent;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaFlowState;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaProcessingContext;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.action.MfaAction;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.config.MfaStateMachineConfigurator;
import io.springsecurity.springsecurity6x.security.mfa.statemachine.config.MfaStateMachineDefinition;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.io.IOException;
import java.util.Optional;

/**
 * MFA 상태 머신을 실행하고 관리하는 서비스.
 * FactorContext (확장 상태)를 기반으로 현재 상태를 유지하고,
 * 이벤트를 받아 상태 전이를 처리합니다.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class MfaStateMachineService {

    private final MfaStateMachineConfigurator stateMachineConfigurator;
    private final ContextPersistence contextPersistence; // FactorContext 영속화
    // 리스너/인터셉터 주입 (필요시)
    // private final List<MfaStateMachineListener> listeners;

    /**
     * MFA 흐름을 시작하거나 기존 흐름을 이어갑니다.
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param primaryAuthentication 1차 인증 성공 후의 Authentication 객체
     * @param mfaFlowConfig 사용할 MFA 플로우 설정
     * @param initialEvent 상태 머신을 시작하거나 특정 상태로 진입시키기 위한 초기 이벤트 (예: PRIMARY_AUTH_COMPLETED)
     * @param initialPayload 초기 이벤트와 함께 전달될 페이로드
     */
    public void startOrContinueFlow(HttpServletRequest request, HttpServletResponse response,
                                    Authentication primaryAuthentication,
                                    AuthenticationFlowConfig mfaFlowConfig,
                                    MfaEvent initialEvent, @Nullable MfaEventPayload initialPayload)
            throws IOException, ServletException {

        FactorContext factorContext = contextPersistence.contextLoad(request);
        MfaStateMachineDefinition definition = stateMachineConfigurator.buildDefinition(mfaFlowConfig); // 매번 빌드? 또는 캐싱?

        if (factorContext == null) { // 새로운 MFA 흐름 시작
            Assert.notNull(primaryAuthentication, "PrimaryAuthentication cannot be null for new MFA flow");
            String sessionId = request.getSession().getId(); // 또는 더 강력한 ID 생성
            factorContext = new FactorContext(sessionId, primaryAuthentication, definition.getInitialState(), mfaFlowConfig.getTypeName());
            log.info("New MFA flow started for user '{}', flow '{}'. Initial state: {}. Triggering event: {}",
                    factorContext.getUsername(), mfaFlowConfig.getTypeName(), factorContext.getCurrentState(), initialEvent);
        } else { // 기존 MFA 흐름 이어가기
            log.info("Continuing MFA flow for user '{}', flow '{}'. Current state: {}. Received event: {}",
                    factorContext.getUsername(), mfaFlowConfig.getTypeName(), factorContext.getCurrentState(), initialEvent);
            // FactorContext의 상태가 상태 머신 정의의 상태와 일치하는지 확인 필요
            if (!definition.getStates().contains(factorContext.getCurrentState())) {
                log.error("FactorContext state {} is not valid for state machine definition of flow {}. Resetting to initial.",
                        factorContext.getCurrentState(), mfaFlowConfig.getTypeName());
                factorContext.changeState(definition.getInitialState());
                // 또는 에러 처리
            }
        }

        // 이벤트 처리
        processEvent(request, response, factorContext, mfaFlowConfig, definition, initialEvent, initialPayload, primaryAuthentication);
    }


    /**
     * 상태 머신에 이벤트를 전송하고 상태 전이를 처리합니다.
     */
    public void sendEvent(HttpServletRequest request, HttpServletResponse response,
                          AuthenticationFlowConfig mfaFlowConfig,
                          MfaEvent event, @Nullable MfaEventPayload payload,
                          @Nullable Authentication currentAuthentication) // 현재 단계의 인증 객체 (1차 또는 2차 요소 성공 후)
            throws IOException, ServletException {

        FactorContext factorContext = contextPersistence.contextLoad(request);
        if (factorContext == null) {
            log.warn("Cannot send event '{}': No FactorContext found for user. MFA flow might not have started or session expired.", event);
            // 적절한 예외 처리 또는 리디렉션
            response.sendRedirect(request.getContextPath() + "/login?error=mfa_session_expired"); // 예시
            return;
        }
        if (!factorContext.getFlowTypeName().equals(mfaFlowConfig.getTypeName())) {
            log.error("FlowConfig mismatch! FactorContext flow: {}, Event for flow: {}. Aborting event processing.",
                    factorContext.getFlowTypeName(), mfaFlowConfig.getTypeName());
            // 예외 처리
            return;
        }


        MfaStateMachineDefinition definition = stateMachineConfigurator.buildDefinition(mfaFlowConfig);
        log.info("Sending event '{}' to MFA state machine for user '{}'. Current state: {}",
                event, factorContext.getUsername(), factorContext.getCurrentState());

        processEvent(request, response, factorContext, mfaFlowConfig, definition, event, payload,
                currentAuthentication != null ? currentAuthentication : factorContext.getPrimaryAuthentication());
    }


    private void processEvent(HttpServletRequest request, HttpServletResponse response,
                              FactorContext factorContext, AuthenticationFlowConfig mfaFlowConfig,
                              MfaStateMachineDefinition definition,
                              MfaEvent event, @Nullable MfaEventPayload payload,
                              Authentication currentAuthentication)
            throws IOException, ServletException {

        MfaState currentState = factorContext.getCurrentState();

        Optional<MfaStateMachineDefinition.Transition> matchingTransition = definition.getTransitions().stream()
                .filter(t -> t.getSource() == currentState && t.getEvent() == event)
                .filter(t -> { // Guard 조건 평가
                    MfaProcessingContext processingContext = MfaProcessingContext.builder()
                            .factorContext(factorContext)
                            .flowConfig(mfaFlowConfig)
                            .event(event)
                            .payload(payload)
                            .currentAuthentication(currentAuthentication)
                            .request(request).response(response)
                            .build();
                    return t.getGuard() == null || t.getGuard().evaluate(processingContext);
                })
                .findFirst(); // 여러 전이가 매칭될 경우? (일반적으로는 단일 매칭 가정)

        if (matchingTransition.isPresent()) {
            MfaStateMachineDefinition.Transition transition = matchingTransition.get();
            MfaState targetState = transition.getTarget();

            log.info("MFA Transition: User '{}', Flow '{}': From State [{}] To State [{}] On Event [{}].",
                    factorContext.getUsername(), mfaFlowConfig.getTypeName(), currentState, targetState, event);

            // 전이 액션 수행
            if (transition.getAction() != null) {
                log.debug("Executing transition action: {}", transition.getAction().getClass().getSimpleName());
                MfaProcessingContext processingContext = MfaProcessingContext.builder()
                        .factorContext(factorContext)
                        .flowConfig(mfaFlowConfig)
                        .event(event)
                        .payload(payload)
                        .currentAuthentication(currentAuthentication)
                        .request(request).response(response)
                        .build();
                transition.getAction().execute(processingContext);
            }

            // 상태 변경
            factorContext.changeState(targetState);

            // 새로운 상태 진입 액션 수행 (정의되어 있다면)
            MfaAction entryAction = definition.getEntryActions().get(targetState);
            if (entryAction != null) {
                log.debug("Executing entry action for state {}: {}", targetState, entryAction.getClass().getSimpleName());
                MfaProcessingContext processingContext = MfaProcessingContext.builder()
                        .factorContext(factorContext)
                        .flowConfig(mfaFlowConfig)
                        .event(event) // 진입 시점에는 이벤트가 없을 수도 있음 (전이 이벤트와 다름)
                        .payload(payload)
                        .currentAuthentication(currentAuthentication)
                        .request(request).response(response)
                        .build();
                entryAction.execute(processingContext);
            }

            // FactorContext (및 상태 머신 상태) 영속화
            contextPersistence.saveContext(factorContext, request);

            // 종료 상태 도달 시 컨텍스트 정리
            if (targetState == definition.getEndState() || targetState.isTerminal()) { // MfaFlowState에 isTerminal() 추가
                log.info("MFA flow for user '{}' reached terminal state: {}. Cleaning up context.",
                        factorContext.getUsername(), targetState);
                contextPersistence.deleteContext(request);
            }

        } else {
            log.warn("MFA No Transition: User '{}', Flow '{}': No valid transition found for Event [{}] from State [{}]. Event ignored.",
                    factorContext.getUsername(), mfaFlowConfig.getTypeName(), event, currentState);
            // 이벤트가 처리되지 않았음을 알리거나, 예외적인 상황으로 간주할 수 있음
        }
    }
}