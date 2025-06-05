package io.springsecurity.springsecurity6x.security.statemachine.config;

import io.springsecurity.springsecurity6x.security.config.redis.UnifiedRedisConfiguration;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.config.kyro.MfaKryoStateMachineSerialisationService;
import io.springsecurity.springsecurity6x.security.statemachine.core.event.MfaEventPublisher;
import io.springsecurity.springsecurity6x.security.statemachine.core.persist.InMemoryStateMachinePersist;
import io.springsecurity.springsecurity6x.security.statemachine.core.persist.ResilientRedisStateMachinePersist;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.statemachine.listener.MfaStateChangeListener;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.aop.framework.ProxyFactoryBean;
import org.springframework.aop.target.CommonsPool2TargetSource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.*;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.StateMachinePersist;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.data.redis.*;
import org.springframework.statemachine.persist.DefaultStateMachinePersister;
import org.springframework.statemachine.persist.StateMachinePersister;

/**
 * 통합 State Machine 설정 - 간소화 버전
 *
 * 삭제/수정 사항:
 * - stateMachineProperties() 메서드 삭제 (이미 @EnableConfigurationProperties로 등록됨)
 * - @ConditionalOnMissingBean 제거 (불필요)
 * - @Primary 중복 제거
 */
@Slf4j
@Configuration
@Import({UnifiedRedisConfiguration.class, AsyncEventConfiguration.class})
@EnableConfigurationProperties({StateMachineProperties.class, AuthContextProperties.class})
@RequiredArgsConstructor
public class UnifiedStateMachineConfiguration {

    private final StateMachineProperties properties;
    private final AuthContextProperties authContextProperties;


    /**
     * State Machine 영속화 전략
     */
//    @Bean
    public StateMachinePersist<MfaState, MfaEvent, String> stateMachinePersist(
            @Qualifier("stateMachineRedisTemplate") RedisTemplate<String, Object> redisTemplate) {

        String persistenceType = properties.getPersistence() != null ?
                properties.getPersistence().getType() : "memory";

        log.info("Configuring State Machine persistence with type: {}", persistenceType);

        switch (persistenceType.toLowerCase()) {
            case "redis":
                StateMachinePersist<MfaState, MfaEvent, String> fallback = null;
                if (properties.getPersistence() != null && properties.getPersistence().isEnableFallback()) {
                    fallback = new InMemoryStateMachinePersist();
                }

                int ttlMinutes = properties.getPersistence() != null && properties.getPersistence().getTtlMinutes() != null
                        ? properties.getPersistence().getTtlMinutes() : 30;

                return new ResilientRedisStateMachinePersist(redisTemplate, fallback, ttlMinutes);

            case "memory":
            default:
                return new InMemoryStateMachinePersist();
        }
    }

    @Bean
    public RedisRepositoryStateMachinePersist<MfaState, MfaEvent> stateMachinePersist(RedisStateMachineRepository redisStateMachineRepository) {
       MfaKryoStateMachineSerialisationService kryoStateMachineSerialisationService =
               new MfaKryoStateMachineSerialisationService();
        return new RedisRepositoryStateMachinePersist(redisStateMachineRepository, kryoStateMachineSerialisationService);
    }


    @Bean
    public StateMachinePersister<MfaState, MfaEvent,String> stateMachineRuntimePersister(
            RedisRepositoryStateMachinePersist<MfaState, MfaEvent> stateMachinePersist) {
        RedisPersistingStateMachineInterceptor<MfaState, MfaEvent, Object> stateMachineInterceptor
                = new RedisPersistingStateMachineInterceptor<>(stateMachinePersist);
        return new DefaultStateMachinePersister(stateMachineInterceptor);

    }

 /*   @Bean
    public RedisStateMachinePersister<MfaState, MfaEvent> redisStateMachinePersister(
            StateMachinePersist<MfaState, MfaEvent, String> stateMachinePersist) {
        return new RedisStateMachinePersister<>(stateMachinePersist);
    }*/


   /* @Bean
    public StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister(RedisConnectionFactory connectionFactory) {
        RedisStateMachineContextRepository<MfaState, MfaEvent> repository =
                new RedisStateMachineContextRepository<>(connectionFactory);
        StateMachinePersist<MfaState, MfaEvent, String> persist = new RepositoryStateMachinePersist<>(repository);
        return new DefaultStateMachinePersister<>(persist);
    }*/

    // 1. 상태 머신 템플릿 빈 (프로토타입)
    @Bean(name = "mfaStateMachineTarget")
    @Scope("prototype")
    public StateMachine<MfaState, MfaEvent> mfaStateMachineTarget(StateMachineFactory<MfaState, MfaEvent> stateMachineFactory) throws Exception {
        return stateMachineFactory.getStateMachine();
    }

    // 2. Commons Pool2 타겟 소스
    @Bean
    public CommonsPool2TargetSource poolTargetSource() {
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
    @Primary
    @Scope(value = "request", proxyMode = ScopedProxyMode.TARGET_CLASS) // 예시: 요청 스코프
    // @Scope(value = "prototype", proxyMode = ScopedProxyMode.TARGET_CLASS) // 또는 매번 새 프록시(풀에서 가져옴)
    public StateMachine<MfaState, MfaEvent> pooledMfaStateMachine(@Qualifier("poolTargetSource") CommonsPool2TargetSource targetSource) {
        ProxyFactoryBean pfb = new ProxyFactoryBean();
        pfb.setTargetSource(targetSource);
        pfb.setInterfaces(StateMachine.class);
        return (StateMachine<MfaState, MfaEvent>) pfb.getObject();
    }



    /**
     * MFA 이벤트 발행자
     */
    @Bean
    public MfaEventPublisher mfaEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        log.info("Creating MFA Event Publisher");
        return new MfaEventPublisher(applicationEventPublisher);
    }


    /**
     * State Change Listener (메트릭 수집용)
     */
    @Bean
    @ConditionalOnProperty(prefix = "spring.auth.mfa", name = "metrics-enabled", havingValue = "true", matchIfMissing = true)
    public MfaStateChangeListener mfaStateChangeListener() {
        log.info("Enabling MFA State Change Listener for metrics");
        return new MfaStateChangeListener();
    }
}