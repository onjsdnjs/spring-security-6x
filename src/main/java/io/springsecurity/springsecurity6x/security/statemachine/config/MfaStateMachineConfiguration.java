package io.springsecurity.springsecurity6x.security.statemachine.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.statemachine.config.EnableStateMachineFactory;
import org.springframework.statemachine.config.StateMachineConfigurerAdapter;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.config.builders.StateMachineConfigurationConfigurer;
import org.springframework.statemachine.config.builders.StateMachineStateConfigurer;
import org.springframework.statemachine.config.builders.StateMachineTransitionConfigurer;

import java.util.EnumSet;

/**
 * MFA State Machine 구성
 */
@Slf4j
@Configuration
@EnableStateMachineFactory
@RequiredArgsConstructor
public class MfaStateMachineConfiguration extends StateMachineConfigurerAdapter<MfaState, MfaEvent> {

    @Override
    public void configure(StateMachineConfigurationConfigurer<MfaState, MfaEvent> config) throws Exception {
        config
                .withConfiguration()
                .autoStartup(false)
                .machineId("mfaStateMachine");
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
                .and()

                // MFA 시작
                .withExternal()
                .source(MfaState.START_MFA)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.MFA_REQUIRED_SELECT_FACTOR)
                .and()

                // 팩터 선택
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_SELECTION)
                .target(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .event(MfaEvent.FACTOR_SELECTED)
                .and()

                // 챌린지 시작
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .event(MfaEvent.CHALLENGE_INITIATED_SUCCESSFULLY)
                .and()

                // 검증 성공
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .target(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .event(MfaEvent.FACTOR_VERIFIED_SUCCESS)
                .and()

                // 모든 팩터 완료
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .target(MfaState.ALL_FACTORS_COMPLETED)
                .event(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED)
                .and()

                // 최종 성공
                .withExternal()
                .source(MfaState.ALL_FACTORS_COMPLETED)
                .target(MfaState.MFA_SUCCESSFUL)
                .event(MfaEvent.ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN);
    }

    /**
     * StateMachineFactory 반환 메서드
     */
    public StateMachineFactory<MfaState, MfaEvent> getStateMachineFactory() throws Exception {
        return new org.springframework.statemachine.config.StateMachineBuilder.Builder<MfaState, MfaEvent>()
                .configureConfiguration()
                .withConfiguration()
                .autoStartup(false)
                .machineId("mfaStateMachine")
                .and()
                .configureStates()
                .withStates()
                .initial(MfaState.NONE)
                .states(EnumSet.allOf(MfaState.class))
                .and()
                .configureTransitions()
                .withExternal()
                .source(MfaState.NONE)
                .target(MfaState.START_MFA)
                .event(MfaEvent.PRIMARY_AUTH_SUCCESS)
                .and()
                .build();
    }
}