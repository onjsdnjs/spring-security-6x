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
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.util.Assert;

import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;


public abstract class AbstractFlowRegistrar implements SecurityPlatformDsl {
    protected final PlatformConfig.Builder platformBuilder;
    private final StateSetter stateSetter;
    protected ApplicationContext applicationContext; // MfaDslConfigurerImpl 생성 시 사용하기 위해 추가 (필드 주입 또는 setter 주입 필요)

    protected AbstractFlowRegistrar(PlatformConfig.Builder platformBuilder) {
        this.platformBuilder = platformBuilder;
        this.stateSetter = new StateSetter();
    }

    // ApplicationContext를 설정하기 위한 setter 메소드 (또는 생성자 오버로딩)
    // IdentityDslRegistry가 ApplicationContext를 주입받아 이 메소드를 호출하도록 할 수 있음
    // 또는 IdentityDslRegistry가 ApplicationContext를 필드로 직접 관리하고 registerMultiStepFlow 에 전달
    public void applicationContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    protected <S extends StepDslConfigurer> IdentityStateDsl registerFlow(
            AuthType type,
            Customizer<S> customizer,
            // ApplicationContext가 필요한 ConfigurerImpl을 위해 BiFunction 사용 고려
            // Function<AuthenticationStepConfig, S> factory
            // 또는 factory가 ApplicationContext를 어떻게든 접근할 수 있도록 해야함.
            // 가장 간단한 방법은 IdentityDslRegistry가 Context를 갖고, 람다에서 사용.
            // 여기서는 Function<AuthenticationStepConfig, S>를 유지하고,
            // 호출부(IdentityDslRegistry)에서 new XxxConfigurerImpl(stepConfig, this.applicationContext) 형태로 사용한다고 가정.
            // 즉, 각 XxxConfigurerImpl 생성자가 ApplicationContext를 받을 수 있어야 함 (선택적으로).
            Function<AuthenticationStepConfig, S> factory) {

        AuthenticationStepConfig stepConfig = new AuthenticationStepConfig();
        S impl = factory.apply(stepConfig);
        customizer.customize(impl);
        AuthenticationStepConfig step = impl.toConfig();

        AuthenticationFlowConfig.Builder flowBuilder = AuthenticationFlowConfig.builder(type.name().toLowerCase())
                // .stepConfigs(List.of(step)) // AuthenticationFlowConfig 변경에 따라 수정
                .stepConfigs(List.of(step)) // 단일 인증 스텝용 새 필드 사용
                .stateConfig(null)
                .order(impl.getOrder()); // getOrder() 사용
        // .customizer(http -> {}) // 이 부분은 AuthenticationFeature에서 HttpSecurity를 직접 다루므로 제거 또는 다른 방식

        platformBuilder.addFlow(flowBuilder.build());
        return stateSetter;
    }

    // MfaDslConfigurerImpl 생성 시 ApplicationContext 를 전달할 수 있도록 factory 시그니처 변경
    protected IdentityStateDsl registerMultiStepFlow(
            Customizer<MfaDslConfigurer> customizer,
            BiFunction<AuthenticationFlowConfig.Builder, ApplicationContext, MfaDslConfigurer> factory) { // BiFunction으로 변경

        AuthenticationFlowConfig.Builder flowBuilder = AuthenticationFlowConfig.builder(AuthType.MFA.name().toLowerCase());
        // IdentityDslRegistry 에서 주입받은 applicationContext를 여기서 전달
        Assert.notNull(this.applicationContext, "ApplicationContext must be set in AbstractFlowRegistrar before registering MFA flow.");
        MfaDslConfigurer configurer = factory.apply(flowBuilder, this.applicationContext); // applicationContext 전달
        customizer.customize(configurer);
        AuthenticationFlowConfig flow = configurer.build();
        platformBuilder.addFlow(flow);
        return stateSetter;
    }

    private void replaceLastState(String state) {
        var flows = platformBuilder.build().getFlows();
        if (flows.isEmpty()) {
            // 이전에 추가된 flow가 없을 경우 예외 처리 또는 로깅
            // 예를 들어, global()만 호출되고 mfa()나 form() 등이 호출되지 않은 경우
            System.err.println("Warning: No flow to replace state for. State '" + state + "' will not be applied.");
            return;
        }
        var old = flows.getLast();
        // AuthenticationFlowConfig.Builder의 생성자 또는 setter를 사용하여 기존 값 복사
        AuthenticationFlowConfig.Builder updatedBuilder = AuthenticationFlowConfig.builder(old.getTypeName())
                // .stepConfigs(old.stepConfigs()) // 이 필드는 MFA 플로우와 단일 플로우에서 다르게 관리됨
                .order(old.getOrder())
                .rawHttpCustomizer(old.getRawHttpCustomizer()); // rawHttpCustomizer 추가

        // 기존 필드들을 새로운 Builder에 복사 (MFA 플로우와 단일 플로우 구분 필요)
        if (AuthType.MFA.name().equalsIgnoreCase(old.getTypeName())) {
            updatedBuilder.primaryAuthenticationOptions(old.getPrimaryAuthenticationOptions())
                    .mfaPolicyProvider(old.getMfaPolicyProvider())
                    .mfaContinuationHandler(old.getMfaContinuationHandler())
                    .mfaFailureHandler(old.getMfaFailureHandler())
                    .finalSuccessHandler(old.getFinalSuccessHandler())
                    .registeredFactorOptions(old.getRegisteredFactorOptions())
                    .defaultRetryPolicy(old.getDefaultRetryPolicy())
                    .defaultAdaptiveConfig(old.getDefaultAdaptiveConfig())
                    .defaultDeviceTrustEnabled(old.isDefaultDeviceTrustEnabled());
        } else {
            updatedBuilder.stepConfigs(old.getStepConfigs());
        }
        // 상태 설정
        updatedBuilder.stateConfig(new StateConfig(state));

        platformBuilder.replaceLastFlow(updatedBuilder.build());
    }

    private class StateSetter implements IdentityStateDsl {
        @Override
        public SecurityPlatformDsl session(Customizer<SessionStateConfigurer> customizer) {
            replaceLastState(StateType.SESSION.name().toLowerCase());
            // SessionStateConfigurer에 대한 Customizer 적용 로직 추가 필요 (StateFeature에서 처리)
            return AbstractFlowRegistrar.this;
        }

        @Override
        public SecurityPlatformDsl jwt(Customizer<JwtStateConfigurer> customizer) {
            replaceLastState(StateType.JWT.name().toLowerCase());
            // JwtStateConfigurer에 대한 Customizer 적용 로직 추가 필요 (StateFeature에서 처리)
            return AbstractFlowRegistrar.this;
        }

        @Override
        public SecurityPlatformDsl oauth2(Customizer<OAuth2StateConfigurer> customizer) {
            replaceLastState(StateType.OAUTH2.name().toLowerCase());
            // OAuth2StateConfigurer에 대한 Customizer 적용 로직 추가 필요 (StateFeature에서 처리)
            return AbstractFlowRegistrar.this;
        }
    }
}
