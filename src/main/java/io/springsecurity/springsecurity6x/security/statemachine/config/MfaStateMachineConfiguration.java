package io.springsecurity.springsecurity6x.security.statemachine.config;

import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.action.*;
import io.springsecurity.springsecurity6x.security.statemachine.guard.AllFactorsCompletedGuard;
import io.springsecurity.springsecurity6x.security.statemachine.guard.FactorAvailabilityGuard;
import io.springsecurity.springsecurity6x.security.statemachine.guard.MfaPolicyGuard;
import io.springsecurity.springsecurity6x.security.statemachine.guard.RetryLimitGuard;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.statemachine.config.EnableStateMachineFactory;
import org.springframework.statemachine.config.StateMachineConfigurerAdapter;
import org.springframework.statemachine.config.builders.StateMachineConfigurationConfigurer;
import org.springframework.statemachine.config.builders.StateMachineStateConfigurer;
import org.springframework.statemachine.config.builders.StateMachineTransitionConfigurer;
import org.springframework.statemachine.listener.StateMachineListener;
import org.springframework.statemachine.listener.StateMachineListenerAdapter;
import org.springframework.statemachine.state.State;

import java.util.EnumSet;

/**
 * MFA State Machine 설정
 * Spring State Machine의 설정을 정의
 */
@Slf4j
@Configuration
@EnableStateMachineFactory
@RequiredArgsConstructor
public class MfaStateMachineConfiguration extends StateMachineConfigurerAdapter<MfaState, MfaEvent> {

    // Actions
    private final InitializeMfaAction initializeMfaAction;
    private final SelectFactorAction selectFactorAction;
    private final InitiateChallengeAction initiateChallengeAction;
    private final VerifyFactorAction verifyFactorAction;
    private final CompleteMfaAction completeMfaAction;
    private final HandleFailureAction handleFailureAction;

    // Guards
    private final MfaPolicyGuard mfaPolicyGuard;
    private final RetryLimitGuard retryLimitGuard;
    private final FactorAvailabilityGuard factorAvailabilityGuard;
    private final AllFactorsCompletedGuard allFactorsCompletedGuard;

    @Override
    public void configure(StateMachineConfigurationConfigurer<MfaState, MfaEvent> config) throws Exception {
        config
                .withConfiguration()
                .autoStartup(false) // 명시적 시작 필요
                .listener(stateMachineListener());
    }

    @Override
    public void configure(StateMachineStateConfigurer<MfaState, MfaEvent> states) throws Exception {
        states
                .withStates()
                .initial(MfaState.START_MFA)
                .end(MfaState.MFA_SUCCESSFUL)
                .end(MfaState.MFA_FAILED_TERMINAL)
                .end(MfaState.MFA_CANCELLED)
                .end(MfaState.MFA_SESSION_EXPIRED)
                .states(EnumSet.allOf(MfaState.class));
    }

    @Override
    public void configure(StateMachineTransitionConfigurer<MfaState, MfaEvent> transitions) throws Exception {
        transitions
                // ===== 초기 상태에서의 전이 =====
                .withExternal()
                .source(MfaState.START_MFA)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.MFA_REQUIRED_SELECT_FACTOR)
                .action(initializeMfaAction)
                .guard(mfaPolicyGuard)

                .and()
                .withExternal()
                .source(MfaState.START_MFA)
                .target(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .event(MfaEvent.MFA_REQUIRED_INITIATE_CHALLENGE)
                .action(initializeMfaAction)
                .guard(mfaPolicyGuard)

                .and()
                .withExternal()
                .source(MfaState.START_MFA)
                .target(MfaState.ALL_FACTORS_COMPLETED)
                .event(MfaEvent.MFA_NOT_REQUIRED)

                // ===== Factor 선택 상태에서의 전이 =====
                .and()
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_SELECTION)
                .target(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .event(MfaEvent.FACTOR_SELECTED_OTT)
                .action(selectFactorAction)
                .guard(factorAvailabilityGuard)

                .and()
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_SELECTION)
                .target(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .event(MfaEvent.FACTOR_SELECTED_PASSKEY)
                .action(selectFactorAction)
                .guard(factorAvailabilityGuard)

                // ===== Challenge 시작 상태에서의 전이 =====
                .and()
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .target(MfaState.FACTOR_CHALLENGE_SENT_AWAITING_UI)
                .event(MfaEvent.INITIATE_CHALLENGE)
                .action(initiateChallengeAction)

                .and()
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_SENT_AWAITING_UI)
                .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .event(MfaEvent.CHALLENGE_ISSUED_SUCCESSFULLY)

                .and()
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_SENT_AWAITING_UI)
                .target(MfaState.MFA_FAILED_TERMINAL)
                .event(MfaEvent.CHALLENGE_ISSUANCE_FAILED)
                .action(handleFailureAction)

                // ===== Factor 검증 상태에서의 전이 =====
                .and()
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .target(MfaState.FACTOR_VERIFICATION_IN_PROGRESS)
                .event(MfaEvent.SUBMIT_FACTOR_CREDENTIAL)

                .and()
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_IN_PROGRESS)
                .target(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .event(MfaEvent.FACTOR_VERIFIED_SUCCESS)
                .action(verifyFactorAction)

                .and()
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_IN_PROGRESS)
                .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .event(MfaEvent.FACTOR_VERIFICATION_FAILED)
                .guard(retryLimitGuard)
                .action(handleFailureAction)

                .and()
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_IN_PROGRESS)
                .target(MfaState.MFA_FAILED_TERMINAL)
                .event(MfaEvent.RETRY_LIMIT_EXCEEDED)
                .action(handleFailureAction)

                // ===== Factor 완료 후 전이 =====
                .and()
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.FACTOR_VERIFIED_SUCCESS)
                .guard((context) -> !allFactorsCompletedGuard.evaluate(context)) // negate 대신 람다 사용

                .and()
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .target(MfaState.ALL_FACTORS_COMPLETED)
                .event(MfaEvent.FACTOR_VERIFIED_SUCCESS)
                .guard(allFactorsCompletedGuard)

                // ===== 최종 성공 전이 =====
                .and()
                .withExternal()
                .source(MfaState.ALL_FACTORS_COMPLETED)
                .target(MfaState.MFA_SUCCESSFUL)
                .event(MfaEvent.ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN)
                .action(completeMfaAction)

                // ===== 취소 및 타임아웃 전이 (여러 상태에서 가능) =====
                .and()
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_SELECTION)
                .target(MfaState.MFA_CANCELLED)
                .event(MfaEvent.USER_ABORTED_MFA)

                .and()
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .target(MfaState.MFA_CANCELLED)
                .event(MfaEvent.USER_ABORTED_MFA)

                .and()
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_SELECTION)
                .target(MfaState.MFA_SESSION_EXPIRED)
                .event(MfaEvent.SESSION_TIMEOUT)

                .and()
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .target(MfaState.MFA_SESSION_EXPIRED)
                .event(MfaEvent.SESSION_TIMEOUT);
    }

    @Bean
    public StateMachineListener<MfaState, MfaEvent> stateMachineListener() {
        return new StateMachineListenerAdapter<MfaState, MfaEvent>() {
            @Override
            public void stateChanged(State<MfaState, MfaEvent> from, State<MfaState, MfaEvent> to) {
                log.info("State changed from {} to {}",
                        from != null ? from.getId() : "NONE",
                        to != null ? to.getId() : "NONE");
            }

            @Override
            public void eventNotAccepted(org.springframework.messaging.Message<MfaEvent> event) {
                log.warn("Event not accepted: {}", event.getPayload());
            }
        };
    }
}