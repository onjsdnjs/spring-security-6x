package io.springsecurity.springsecurity6x.security.statemachine.config;

import io.springsecurity.springsecurity6x.security.statemachine.action.*;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.guard.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RedissonClient;
import org.springframework.aop.framework.ProxyFactoryBean;
import org.springframework.aop.target.CommonsPool2TargetSource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.StateMachinePersist;
import org.springframework.statemachine.config.EnableStateMachineFactory;
import org.springframework.statemachine.config.EnumStateMachineConfigurerAdapter;
import org.springframework.statemachine.config.StateMachineBuilder;
import org.springframework.statemachine.config.builders.StateMachineConfigurationConfigurer;
import org.springframework.statemachine.config.builders.StateMachineStateConfigurer;
import org.springframework.statemachine.config.builders.StateMachineTransitionConfigurer;
import org.springframework.statemachine.config.configurers.StateConfigurer;
import org.springframework.statemachine.config.configurers.TransitionConfigurer;
import org.springframework.statemachine.data.redis.RedisStateMachineContextRepository;
import org.springframework.statemachine.listener.StateMachineListener;
import org.springframework.statemachine.listener.StateMachineListenerAdapter;
import org.springframework.statemachine.persist.DefaultStateMachinePersister;
import org.springframework.statemachine.persist.RepositoryStateMachinePersist;
import org.springframework.statemachine.persist.StateMachinePersister;
import org.springframework.statemachine.state.State;

import java.util.EnumSet;

@Slf4j
@Configuration
//@EnableStateMachineFactory
@RequiredArgsConstructor
public class MfaStateMachineConfiguration {

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

    @Bean
    public StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister(RedisConnectionFactory connectionFactory) {
        RedisStateMachineContextRepository<MfaState, MfaEvent> repository =
                new RedisStateMachineContextRepository<>(connectionFactory);
        StateMachinePersist<MfaState, MfaEvent, String> persist = new RepositoryStateMachinePersist<>(repository);
        return new DefaultStateMachinePersister<>(persist);
    }

    // 1. 상태 머신 템플릿 빈 (프로토타입)
    @Bean(name = "mfaStateMachineTarget")
    @Scope("prototype")
    public StateMachine<MfaState, MfaEvent> mfaStateMachineTarget() throws Exception {
        StateMachineBuilder.Builder<MfaState, MfaEvent> builder = StateMachineBuilder.builder();

        configureMfaStateMachine(builder.configureConfiguration(),
                builder.configureStates(),
                builder.configureTransitions());

        StateMachine<MfaState, MfaEvent> sm = builder.build();
        // 프로토타입이므로 autoStartup(true)를 빌더에서 설정하거나,
        // 풀에서 가져온 후 수동으로 시작해야 할 수 있음.
        // 일반적으로 풀링될 객체는 autoStartup(true)로 설정.
        return sm;
    }

    // 2. Commons Pool2 타겟 소스
    @Bean
    public CommonsPool2TargetSource mfaStateMachinePoolTargetSource() {
        CommonsPool2TargetSource pool = new CommonsPool2TargetSource();
        pool.setTargetBeanName("mfaStateMachineTarget"); // 프로토타입 빈 이름
        pool.setMaxSize(10); // 풀 최대 크기 (설정값으로 관리 권장)

        return pool;
    }

    // 3. 풀링된 상태 머신 프록시 빈 (요청 스코프 또는 다른 좁은 스코프)
    // 이 빈을 MfaStateMachineServiceImpl에 주입하여 사용합니다.
    // proxyMode = ScopedProxyMode.INTERFACES를 사용하거나 StateMachine 인터페이스로 캐스팅해야 할 수 있음.
    // 또는 StateMachine<MfaState, MfaEvent> 타입으로 직접 반환 시도.
    @Bean(name = "pooledMfaStateMachine")
    @Scope(value = "request", proxyMode = ScopedProxyMode.TARGET_CLASS) // 예시: 요청 스코프
    // @Scope(value = "prototype", proxyMode = org.springframework.aop.scope.ScopedProxyMode.TARGET_CLASS) // 또는 매번 새 프록시(풀에서 가져옴)
    public StateMachine<MfaState, MfaEvent> pooledMfaStateMachine(
            @Qualifier("mfaStateMachinePoolTargetSource") CommonsPool2TargetSource targetSource) {
        ProxyFactoryBean pfb = new ProxyFactoryBean();
        pfb.setTargetSource(targetSource);
        // StateMachine 인터페이스로 프록시 만들기 위해 인터페이스 지정
        pfb.setInterfaces(StateMachine.class);
        return (StateMachine<MfaState, MfaEvent>) pfb.getObject();
    }

    private void configureMfaStateMachine(
            StateMachineConfigurationConfigurer<MfaState, MfaEvent> configurationConfigurer,
            StateMachineStateConfigurer<MfaState, MfaEvent> statesConfigurer,
            StateMachineTransitionConfigurer<MfaState, MfaEvent> transitionConfigurer) throws Exception {

            configurationConfigurer
                .withConfiguration()
                .autoStartup(true)
                .machineId("mfaPoolMachine")
                .listener(listener());


        statesConfigurer
                .withStates()
                .initial(MfaState.NONE)
                .states(EnumSet.allOf(MfaState.class))
                .end(MfaState.MFA_SUCCESSFUL)
                .end(MfaState.MFA_FAILED_TERMINAL)
                .end(MfaState.MFA_CANCELLED)
                .end(MfaState.MFA_SESSION_EXPIRED)
                .end(MfaState.MFA_NOT_REQUIRED)
                .end(MfaState.MFA_SYSTEM_ERROR)
                .end(MfaState.MFA_SESSION_INVALIDATED);

        transitionConfigurer
                // 초기 전이 - PRIMARY_AUTHENTICATION_COMPLETED로 직접 이동
                .withExternal()
                .source(MfaState.NONE)
                .target(MfaState.PRIMARY_AUTHENTICATION_COMPLETED)
                .event(MfaEvent.PRIMARY_AUTH_SUCCESS)
                .action(initializeMfaAction)
                .and()

                // MFA 정책 평가 결과 - MFA 불필요
                .withExternal()
                .source(MfaState.PRIMARY_AUTHENTICATION_COMPLETED)
                .target(MfaState.MFA_NOT_REQUIRED)
                .event(MfaEvent.MFA_NOT_REQUIRED)
                .and()

                // MFA 정책 평가 결과 - MFA 필요
                .withExternal()
                .source(MfaState.PRIMARY_AUTHENTICATION_COMPLETED)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.MFA_REQUIRED_SELECT_FACTOR)
                .and()

                // MFA 구성 필요
                .withExternal()
                .source(MfaState.PRIMARY_AUTHENTICATION_COMPLETED)
                .target(MfaState.MFA_CONFIGURATION_REQUIRED)
                .event(MfaEvent.MFA_CONFIGURATION_REQUIRED)
                .and()

                // 팩터 선택 후 챌린지 준비 상태로
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_SELECTION)
                .target(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .event(MfaEvent.FACTOR_SELECTED)
                .action(selectFactorAction)
                .and()

                // 자동 선택 경로 (PRIMARY_AUTHENTICATION_COMPLETED → 바로 챌린지)
                .withExternal()
                .source(MfaState.PRIMARY_AUTHENTICATION_COMPLETED)
                .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .event(MfaEvent.INITIATE_CHALLENGE_AUTO)
                .action(initiateChallengeAction)
                .and()

                // 일반 경로 (팩터 선택 후 → 챌린지)
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .event(MfaEvent.INITIATE_CHALLENGE)
                .action(initiateChallengeAction)
                .and()

              /*  // 챌린지 성공적 시작 -> 사용자 입력 대기
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_INITIATED)
                .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .event(MfaEvent.CHALLENGE_INITIATED_SUCCESSFULLY)
                .and()

                // 챌린지 시작 실패 -> 팩터 선택으로 돌아감
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_INITIATED)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.CHALLENGE_INITIATION_FAILED)
                .and()*/

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

                // 모든 팩터 완료 확인 - 성공
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
                .event(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED)
                .guard(allFactorsCompletedGuard.negate())
                .and()

                // 최종 성공
                .withExternal()
                .source(MfaState.ALL_FACTORS_COMPLETED)
                .target(MfaState.MFA_SUCCESSFUL)
                .event(MfaEvent.ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN)
                .action(completeMfaAction)
                .and()

                // 사용자 취소 (다양한 상태에서)
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
                .source(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .target(MfaState.MFA_CANCELLED)
                .event(MfaEvent.USER_ABORTED_MFA)
                .and()

                // 세션 타임아웃 (다양한 상태에서)
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_SELECTION)
                .target(MfaState.MFA_SESSION_EXPIRED)
                .event(MfaEvent.SESSION_TIMEOUT)
                .and()
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .target(MfaState.MFA_SESSION_EXPIRED)
                .event(MfaEvent.SESSION_TIMEOUT)
                .and()
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .target(MfaState.MFA_SESSION_EXPIRED)
                .event(MfaEvent.SESSION_TIMEOUT)
                .and()

                // 챌린지 타임아웃
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.CHALLENGE_TIMEOUT)
                .and()

                // 시스템 에러 처리 (다양한 상태에서)
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_PENDING)
                .target(MfaState.MFA_SYSTEM_ERROR)
                .event(MfaEvent.SYSTEM_ERROR)
                .and()
                .withExternal()
                .source(MfaState.PRIMARY_AUTHENTICATION_COMPLETED)
                .target(MfaState.MFA_SYSTEM_ERROR)
                .event(MfaEvent.SYSTEM_ERROR)
                .and()
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_SELECTION)
                .target(MfaState.MFA_SYSTEM_ERROR)
                .event(MfaEvent.SYSTEM_ERROR)
                .and()
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_INITIATED)
                .target(MfaState.MFA_SYSTEM_ERROR)
                .event(MfaEvent.SYSTEM_ERROR)
                .and()
                .withExternal()
                .source(MfaState.MFA_SUCCESSFUL)
                .target(MfaState.MFA_SYSTEM_ERROR)
                .event(MfaEvent.SYSTEM_ERROR)
                .and()

                // 재시도 한계 초과에서 실패로
                .withExternal()
                .source(MfaState.MFA_RETRY_LIMIT_EXCEEDED)
                .target(MfaState.MFA_FAILED_TERMINAL)
                .event(MfaEvent.SYSTEM_ERROR);
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