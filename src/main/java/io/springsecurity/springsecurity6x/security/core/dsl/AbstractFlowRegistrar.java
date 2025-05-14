package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.MfaDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.StepDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.feature.state.jwt.JwtStateConfigurer;
import io.springsecurity.springsecurity6x.security.core.feature.state.oauth2.OAuth2StateConfigurer;
import io.springsecurity.springsecurity6x.security.core.feature.state.session.SessionStateConfigurer;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.StateType;
import org.springframework.security.config.Customizer;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.List;
import java.util.function.Function;

public abstract class AbstractFlowRegistrar implements SecurityPlatformDsl {
    protected final PlatformConfig.Builder platformBuilder;
    private final StateSetter stateSetter;

    protected AbstractFlowRegistrar(PlatformConfig.Builder platformBuilder) {
        Assert.notNull(platformBuilder, "PlatformConfig.Builder cannot be null");
        this.platformBuilder = platformBuilder;
        this.stateSetter = new StateSetter(this, platformBuilder); // platformBuilder 전달
    }

    /**
     * 단일 스텝으로 구성된 인증 플로우를 등록합니다.
     *
     * @param type AuthType (form, rest 등)
     * @param customizer 해당 스텝의 Configurer를 커스터마이징하는 람다
     * @param factory AuthenticationStepConfig를 받아 해당 스텝의 Configurer (I 타입)를 생성하는 팩토리 함수
     * @param <S> StepDslConfigurer를 확장하는 Configurer 인터페이스 타입
     * @param <I> S 인터페이스를 구현하는 Configurer 구현체 타입
     * @return 상태 설정을 위한 IdentityStateDsl
     */
    protected <S extends StepDslConfigurer, I extends S> IdentityStateDsl registerFlow(
            AuthType type,
            Customizer<S> customizer,
            Function<AuthenticationStepConfig, I> factory) {

        Assert.notNull(type, "AuthType cannot be null");
        Assert.notNull(customizer, "Customizer cannot be null");
        Assert.notNull(factory, "Factory function cannot be null");

        AuthenticationStepConfig stepConfig = new AuthenticationStepConfig(); // 새로운 스텝 설정 객체 생성
        I configurerImpl = factory.apply(stepConfig); // 팩토리를 통해 Configurer 구현체 생성 (stepConfig 주입)
        customizer.customize(configurerImpl); // 사용자 정의 적용
        AuthenticationStepConfig builtStep = configurerImpl.toConfig(); // 최종 스텝 설정 빌드

        AuthenticationFlowConfig flow = AuthenticationFlowConfig.builder(type.name().toLowerCase())
                .stepConfigs(Collections.singletonList(builtStep)) // 단일 스텝으로 구성된 리스트
                .stateConfig(null) // 상태는 StateSetter에서 나중에 설정
                .rawHttpCustomizer(http -> {}) // 기본값 (필요 시 수정)
                .order(configurerImpl.getOrder()) // Configurer에서 정의된 순서 사용
                .build();

        platformBuilder.addFlow(flow);
        return stateSetter;
    }

    /**
     * 다중 스텝(MFA) 플로우를 등록합니다.
     */
    protected IdentityStateDsl registerMultiStepFlow(
            Customizer<MfaDslConfigurer> customizer,
            Function<AuthenticationFlowConfig.Builder, MfaDslConfigurer> factory) {

        Assert.notNull(customizer, "Customizer cannot be null");
        Assert.notNull(factory, "Factory function cannot be null");

        AuthenticationFlowConfig.Builder flowConfigBuilder = AuthenticationFlowConfig.builder(AuthType.MFA.name().toLowerCase());
        MfaDslConfigurer mfaConfigurer = factory.apply(flowConfigBuilder);
        customizer.customize(mfaConfigurer);
        AuthenticationFlowConfig mfaFlow = mfaConfigurer.build();

        platformBuilder.addFlow(mfaFlow);
        return stateSetter;
    }

    private static class StateSetter implements IdentityStateDsl {
        private final SecurityPlatformDsl parentDsl;
        private final PlatformConfig.Builder platformBuilder;

        public StateSetter(SecurityPlatformDsl parentDsl, PlatformConfig.Builder platformBuilder) {
            this.parentDsl = parentDsl;
            this.platformBuilder = platformBuilder;
        }

        private void updateLastFlowState(StateType stateType, Customizer<?> specificConfigurerCustomizer) {
            // specificConfigurerCustomizer는 현재 사용되지 않지만, 향후 확장을 위해 남겨둘 수 있음
            // 예: jwt(jwt -> jwt.issuer("my-issuer")) 와 같이 세부 설정을 하고 싶을 때
            List<AuthenticationFlowConfig> currentFlows = platformBuilder.build().flows(); // getFlows() 추가 필요
            if (currentFlows.isEmpty()) {
                throw new IllegalStateException("Cannot set state as no flow has been registered yet.");
            }
            AuthenticationFlowConfig lastFlow = currentFlows.getLast(); // getLast() 추가 필요
            AuthenticationFlowConfig updatedFlow = AuthenticationFlowConfig.builder(lastFlow.getTypeName())
                    .order(lastFlow.getOrder())
                    .stepConfigs(lastFlow.getStepConfigs()) // getStepConfigs() 추가 필요
                    .rawHttpCustomizer(lastFlow.getRawHttpCustomizer())
                    .stateConfig(new StateConfig(stateType.name().toLowerCase())) // 상태 설정
                    // MFA 관련 필드들도 복사 (MFA 흐름이 마지막에 추가되었을 경우를 대비)
                    .primaryAuthenticationOptions(lastFlow.getPrimaryAuthenticationOptions())
                    .registeredFactorOptions(lastFlow.getRegisteredFactorOptions())
                    .mfaPolicyProvider(lastFlow.getMfaPolicyProvider())
                    .mfaContinuationHandler(lastFlow.getMfaContinuationHandler())
                    .mfaFailureHandler(lastFlow.getMfaFailureHandler())
                    .finalSuccessHandler(lastFlow.getFinalSuccessHandler())
                    .defaultRetryPolicy(lastFlow.getDefaultRetryPolicy())
                    .defaultAdaptiveConfig(lastFlow.getDefaultAdaptiveConfig())
                    .defaultDeviceTrustEnabled(lastFlow.isDefaultDeviceTrustEnabled())
                    .build();
            platformBuilder.replaceLastFlow(updatedFlow);
        }

        @Override
        public SecurityPlatformDsl session(Customizer<SessionStateConfigurer> customizer) {
            updateLastFlowState(StateType.SESSION, customizer);
            return parentDsl;
        }

        @Override
        public SecurityPlatformDsl jwt(Customizer<JwtStateConfigurer> customizer) {
            updateLastFlowState(StateType.JWT, customizer);
            return parentDsl;
        }

        @Override
        public SecurityPlatformDsl oauth2(Customizer<OAuth2StateConfigurer> customizer) {
            updateLastFlowState(StateType.OAUTH2, customizer);
            return parentDsl;
        }
    }
}
