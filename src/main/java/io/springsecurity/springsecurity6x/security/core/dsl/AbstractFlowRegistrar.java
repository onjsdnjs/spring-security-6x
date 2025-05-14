package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.StepDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.MfaDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.feature.state.jwt.JwtStateConfigurer;
import io.springsecurity.springsecurity6x.security.core.feature.state.oauth2.OAuth2StateConfigurer;
import io.springsecurity.springsecurity6x.security.core.feature.state.session.SessionStateConfigurer;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.StateType;
import org.springframework.security.config.Customizer;

import java.util.List;
import java.util.function.Function;

/**
 * 인증 플로우 등록의 공통 로직을 제공하는 추상 클래스
 */
public abstract class AbstractFlowRegistrar implements SecurityPlatformDsl {
    protected final PlatformConfig.Builder platformBuilder;
    private final StateSetter stateSetter;

    protected AbstractFlowRegistrar(PlatformConfig.Builder platformBuilder) {
        this.platformBuilder = platformBuilder;
        this.stateSetter = new StateSetter();
    }

    /**
     * 공통 플로우 등록 메서드
     *
     * @param type       인증 방식 타입
     * @param customizer 스텝 설정 커스터마이저 (FormDslConfigurer 등)
     * @param factory    StepDslConfigurer 구현체 생성 함수
     */
    protected <S extends StepDslConfigurer, I extends S> IdentityStateDsl registerFlow(
            AuthType type,
            Customizer<S> customizer,
            Function<AuthenticationStepConfig, I> factory) {

        AuthenticationStepConfig stepConfig = new AuthenticationStepConfig();
        I impl = factory.apply(stepConfig);
        customizer.customize(impl);
        AuthenticationStepConfig step = impl.toConfig();

        AuthenticationFlowConfig flow = AuthenticationFlowConfig.builder(
                        type.name().toLowerCase()
                )
                .stepConfigs(List.of(step))
                .stateConfig(null)           // 이후 StateSetter 에서 설정
                .customizer(http -> {})
                .order(impl.order())
                .build();

        platformBuilder.addFlow(flow);
        return stateSetter;
    }

    protected IdentityStateDsl registerMultiStepFlow(Customizer<MfaDslConfigurer> customizer,
                                                     Function<AuthenticationFlowConfig.Builder, MfaDslConfigurer> factory) {

        // 1) FlowConfig.Builder 생성
        AuthenticationFlowConfig.Builder flowBuilder = AuthenticationFlowConfig.builder(AuthType.MFA.name().toLowerCase());

        // 2) MfaDslConfigurerImpl 생성 및 DSL 적용
        MfaDslConfigurer configurer = factory.apply(flowBuilder);
        customizer.customize(configurer);

        // 3) 완성된 FlowConfig 생성
        AuthenticationFlowConfig flow = configurer.build();

        // 4) Builder에 등록
        platformBuilder.addFlow(flow);

        // 5) State 설정 DSL 체이닝 포인트 반환
        return stateSetter;
    }

    /**
     * 마지막으로 추가된 플로우에 stateConfig 적용
     */
    private void replaceLastState(String state) {
        var flows = platformBuilder.build().flows();
        var old = flows.getLast();
        var updated = AuthenticationFlowConfig.builder(old.typeName())
                .stepConfigs(old.stepConfigs())
                .stateConfig(new StateConfig(state))
                .customizer(old.customizer())
                .order(old.order())
                .build();
        platformBuilder.replaceLastFlow(updated);
    }

    /**
     * 상태 설정 DSL
     */
    private class StateSetter implements IdentityStateDsl {

        @Override
        public SecurityPlatformDsl session(Customizer<SessionStateConfigurer> customizer) {
            replaceLastState(StateType.SESSION.name().toLowerCase());
            return AbstractFlowRegistrar.this;
        }

        @Override
        public SecurityPlatformDsl jwt(Customizer<JwtStateConfigurer> customizer) {
            replaceLastState(StateType.JWT.name().toLowerCase());
            return AbstractFlowRegistrar.this;
        }

        @Override
        public SecurityPlatformDsl oauth2(Customizer<OAuth2StateConfigurer> customizer) {
            replaceLastState(StateType.OAUTH2.name().toLowerCase());
            return AbstractFlowRegistrar.this;
        }
    }
}
