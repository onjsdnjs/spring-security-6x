package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.AuthenticationFactorConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.MfaDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factory.AuthMethodConfigurerFactory;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.feature.state.jwt.JwtStateConfigurer;
import io.springsecurity.springsecurity6x.security.core.feature.state.oauth2.OAuth2StateConfigurer;
import io.springsecurity.springsecurity6x.security.core.feature.state.session.SessionStateConfigurer;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.StateType;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;

import java.util.List;
import java.util.function.BiFunction;

public abstract class AbstractFlowRegistrar implements SecurityPlatformDsl {
    protected final PlatformConfig.Builder platformBuilder;
    private final StateSetter stateSetter;
    protected ApplicationContext applicationContext;
    private final AuthMethodConfigurerFactory authMethodConfigurerFactory;

    protected AbstractFlowRegistrar(PlatformConfig.Builder platformBuilder, ApplicationContext applicationContext) {
        this.platformBuilder = platformBuilder;
        this.applicationContext = applicationContext;
        this.stateSetter = new StateSetter();
        this.authMethodConfigurerFactory = new AuthMethodConfigurerFactory(applicationContext);
    }

    /**
     * 단일 인증 흐름(Authentication Method)을 등록합니다.
     * @param authType 인증 타입
     * @param configurerCustomizer 해당 인증 타입의 Configurer를 위한 Customizer
     * @param defaultOrder 이 흐름의 기본 순서
     * @param <O> Option 타입
     * @param <C> Configurer 타입
     * @return IdentityStateDsl
     */
    protected <O extends AuthenticationProcessingOptions,
            C extends AuthenticationFactorConfigurer<O, C>>
    IdentityStateDsl registerAuthenticationMethod(
            AuthType authType,
            Customizer<C> configurerCustomizer,
            int defaultOrder) {

        C configurer = authMethodConfigurerFactory.createConfigurer(authType);
        configurerCustomizer.customize(configurer);
        O options = configurer.buildConcreteOptions();

        AuthenticationStepConfig stepConfig = new AuthenticationStepConfig();
        stepConfig.setType(authType.name().toLowerCase());
        stepConfig.getOptions().put("_options", options);
        stepConfig.setOrder(defaultOrder); // 여기서 직접 order 설정

        AuthenticationFlowConfig.Builder flowBuilder = AuthenticationFlowConfig.builder(authType.name().toLowerCase())
                .stepConfigs(List.of(stepConfig))
                .stateConfig(null)
                .order(defaultOrder); // Flow 전체의 order도 step의 order와 동일하게 설정

        platformBuilder.addFlow(flowBuilder.build());
        return stateSetter;
    }

    protected IdentityStateDsl registerMultiStepFlow(
            Customizer<MfaDslConfigurer> customizer,
            BiFunction<AuthenticationFlowConfig.Builder, ApplicationContext, MfaDslConfigurer> factory) {

        AuthenticationFlowConfig.Builder flowBuilderForMfa = AuthenticationFlowConfig.builder(AuthType.MFA.name().toLowerCase());
        MfaDslConfigurer mfaDslConfigurer = factory.apply(flowBuilderForMfa, this.applicationContext);
        customizer.customize(mfaDslConfigurer);
        AuthenticationFlowConfig flow = mfaDslConfigurer.build();
        platformBuilder.addFlow(flow);
        return stateSetter;
    }

    private void replaceLastState(String stateName) {
        List<AuthenticationFlowConfig> currentFlows = platformBuilder.getModifiableFlows();
        if (currentFlows.isEmpty()) {
            System.err.println("Warning: No flow to replace state for. State '" + stateName + "' will not be applied.");
            return;
        }
        int lastIndex = currentFlows.size() - 1;
        AuthenticationFlowConfig lastFlow = currentFlows.get(lastIndex);
        AuthenticationFlowConfig updatedFlow = lastFlow.withStateConfig(new StateConfig(stateName));
        currentFlows.set(lastIndex, updatedFlow);
    }

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
