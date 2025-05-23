package io.springsecurity.springsecurity6x.security.statemachine.config;

import io.springsecurity.springsecurity6x.security.statemachine.action.*;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.guard.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.statemachine.config.EnableStateMachineFactory;
import org.springframework.statemachine.config.EnumStateMachineConfigurerAdapter;
import org.springframework.statemachine.config.builders.StateMachineConfigurationConfigurer;
import org.springframework.statemachine.config.builders.StateMachineStateConfigurer;
import org.springframework.statemachine.config.builders.StateMachineTransitionConfigurer;
import org.springframework.statemachine.listener.StateMachineListener;
import org.springframework.statemachine.listener.StateMachineListenerAdapter;
import org.springframework.statemachine.state.State;

import java.util.EnumSet;

/**
 * MFA State Machine 구성
 */
@Slf4j
@Configuration
@EnableStateMachineFactory
@RequiredArgsConstructor
public class MfaStateMachineConfiguration extends EnumStateMachineConfigurerAdapter<MfaState, MfaEvent> {

    // Actions
    private final InitializeMfaAction initializeMfaAction;
    private final SelectFactorAction selectFactorAction;
    private final InitiateChallengeAction initiateChallengeAction;
    private final VerifyFactorAction verifyFactorAction;
    private final CompleteMfaAction completeMfaAction;
    private final HandleFailureAction handleFailureAction;

    // Guards
    private final AllFactorsCompletedGuard allFactorsCompletedGuard;
    private final RetryLimitGuard retryLimitGuard;

    @Override
    public void configure(StateMachineConfigurationConfigurer<MfaState, MfaEvent> config) throws Exception {
        config
                .withConfiguration()
                .autoStartup(false)
                .machineId("mfaStateMachine")
                .listener(listener());
    }

    @Override
    public void configure(StateMachineStateConfigurer<MfaState, MfaEvent> states) throws Exception {
        states
                .withStates()
                .initial(MfaState.NONE)
                .states(EnumSet.allOf(MfaState.class))
                .end(MfaState.MFA_SUCCESSFUL)
                .end(MfaState.MFA_FAILED_TERMINAL)
                .end(MfaState.MFA_CANCELLED)
                .end(MfaState.MFA_SESSION_EXPIRED);
    }

    @Override
    public void configure(StateMachineTransitionConfigurer<MfaState, MfaEvent> transitions) throws Exception {
        transitions
                // 초기 전이
                .withExternal()
                .source(MfaState.NONE)
                .target(MfaState.START_MFA)
                .event(MfaEvent.PRIMARY_AUTH_SUCCESS)
                .action(initializeMfaAction)
                .and()

                // MFA 시작
                .withExternal()
                .source(MfaState.START_MFA)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.MFA_REQUIRED_SELECT_FACTOR)
                .and()

                // MFA 불필요
                .withExternal()
                .source(MfaState.START_MFA)
                .target(MfaState.MFA_NOT_REQUIRED)
                .event(MfaEvent.MFA_NOT_REQUIRED)
                .and()

                // 팩터 선택
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_SELECTION)
                .target(MfaState.FACTOR_SELECTED)
                .event(MfaEvent.FACTOR_SELECTED)
                .action(selectFactorAction)
                .and()

                // 챌린지 시작
                .withExternal()
                .source(MfaState.FACTOR_SELECTED)
                .target(MfaState.FACTOR_CHALLENGE_INITIATED)
                .event(MfaEvent.INITIATE_CHALLENGE)
                .action(initiateChallengeAction)
                .and()

                // 챌린지 성공
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_INITIATED)
                .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .event(MfaEvent.CHALLENGE_INITIATED_SUCCESSFULLY)
                .and()

                // 검증 시도
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .target(MfaState.FACTOR_VERIFICATION_PENDING)
                .event(MfaEvent.SUBMIT_FACTOR_CREDENTIAL)
                .and()

                // 검증 성공
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_PENDING)
                .target(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .event(MfaEvent.FACTOR_VERIFIED_SUCCESS)
                .action(verifyFactorAction)
                .and()

                // 검증 실패 (재시도 가능)
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_PENDING)
                .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .event(MfaEvent.FACTOR_VERIFICATION_FAILED)
                .guard(retryLimitGuard)
                .action(handleFailureAction)
                .and()

                // 재시도 한계 초과
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_PENDING)
                .target(MfaState.MFA_RETRY_LIMIT_EXCEEDED)
                .event(MfaEvent.RETRY_LIMIT_EXCEEDED)
                .and()

                // 모든 팩터 완료 확인
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .target(MfaState.ALL_FACTORS_COMPLETED)
                .event(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED)
                .guard(allFactorsCompletedGuard)
                .and()

                // 추가 팩터 필요
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .guard(allFactorsCompletedGuard.negate())
                .and()

                // 최종 성공
                .withExternal()
                .source(MfaState.ALL_FACTORS_COMPLETED)
                .target(MfaState.MFA_SUCCESSFUL)
                .event(MfaEvent.ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN)
                .action(completeMfaAction)
                .and()

                // 사용자 취소
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

                // 세션 타임아웃
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
    public StateMachineListener<MfaState, MfaEvent> listener() {
        return new StateMachineListenerAdapter<MfaState, MfaEvent>() {
            @Override
            public void stateChanged(State<MfaState, MfaEvent> from, State<MfaState, MfaEvent> to) {
                if (from != null) {
                    log.info("State changed from {} to {}", from.getId(), to.getId());
                } else {
                    log.info("State machine started with state: {}", to.getId());
                }
            }
        };
    }
}