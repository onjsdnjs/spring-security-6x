package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.BaseAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.AuthenticationFactorConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.MfaDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.MfaDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.factory.AuthMethodConfigurerFactory;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AbstractOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.adapter.state.jwt.JwtStateConfigurer;
import io.springsecurity.springsecurity6x.security.core.adapter.state.oauth2.OAuth2StateConfigurer;
import io.springsecurity.springsecurity6x.security.core.adapter.state.session.SessionStateConfigurer;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.StateType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;

import java.util.List;
import java.util.Objects;

@Slf4j
public abstract class AbstractFlowRegistrar<H extends HttpSecurityBuilder<H>> implements IdentityAuthDsl { // H 제네릭 유지

    protected final PlatformConfig.Builder platformBuilder;
    private final StateSetter stateSetter;
    protected final ApplicationContext applicationContext;
    private final AuthMethodConfigurerFactory authMethodConfigurerFactory;
    // httpSecurityBuilder 필드 제거

    protected AbstractFlowRegistrar(PlatformConfig.Builder platformBuilder,
                                    ApplicationContext applicationContext) { // httpSecurityBuilder 인자 제거
        this.platformBuilder = Objects.requireNonNull(platformBuilder, "platformBuilder cannot be null");
        this.applicationContext = Objects.requireNonNull(applicationContext, "applicationContext cannot be null");
        this.stateSetter = new StateSetter();
        this.authMethodConfigurerFactory = new AuthMethodConfigurerFactory(this.applicationContext);
    }

    protected <O extends AuthenticationProcessingOptions,
            A extends BaseAsepAttributes,
            S extends AuthenticationFactorConfigurer<O, A, S>> IdentityStateDsl registerAuthenticationMethod(
            AuthType authType,
            Customizer<S> configurerCustomizer,
            int defaultOrder,
            Class<S> configurerInterfaceType) {

        // AuthMethodConfigurerFactory는 이제 ApplicationContext만으로 Configurer 생성
        S configurer = authMethodConfigurerFactory.createFactorConfigurer(
                authType,
                configurerInterfaceType
        );

        if (configurer instanceof AbstractOptionsBuilderConfigurer) {
            ((AbstractOptionsBuilderConfigurer<?, ?, ?, ?>) configurer).setApplicationContext(this.applicationContext);
        }

        Objects.requireNonNull(configurerCustomizer, "configurerCustomizer cannot be null").customize(configurer);
        O options = configurer.buildConcreteOptions();

        int actualOrder = defaultOrder;
        if (options instanceof AuthenticationProcessingOptions && ((AuthenticationProcessingOptions) options).getOrder() != 0) {
            actualOrder = ((AuthenticationProcessingOptions) options).getOrder();
        }

        AuthenticationStepConfig stepConfig = new AuthenticationStepConfig();
        stepConfig.setType(authType.name().toLowerCase());
        stepConfig.getOptions().put("_options", options);
        stepConfig.setOrder(actualOrder);

        AuthenticationFlowConfig.Builder flowBuilder = AuthenticationFlowConfig.builder(authType.name().toLowerCase())
                .stepConfigs(List.of(stepConfig))
                .stateConfig(null)
                .order(actualOrder);

        platformBuilder.addFlow(flowBuilder.build());
        log.info("AbstractFlowRegistrar: Registered authentication options for method: {}, Order: {}", authType, actualOrder);
        return this.stateSetter;
    }

    protected IdentityStateDsl registerMultiStepFlow(
            Customizer<MfaDslConfigurer> customizer) {

        // MfaDslConfigurerImpl 생성 시 ApplicationContext만 전달
        MfaDslConfigurerImpl<H> mfaDslConfigurer = // H 제네릭은 형식상 유지
                authMethodConfigurerFactory.createMfaConfigurer(this.applicationContext);
        // mfaDslConfigurer.setApplicationContext(this.applicationContext); // 생성자에서 처리

        Objects.requireNonNull(customizer, "mfa customizer cannot be null").customize(mfaDslConfigurer);
        AuthenticationFlowConfig mfaFlow = mfaDslConfigurer.build();

        platformBuilder.addFlow(mfaFlow);
        log.info("AbstractFlowRegistrar: Registered MFA flow options. Order: {}. Steps: {}", mfaFlow.getOrder(), mfaFlow.getStepConfigs().size());
        return this.stateSetter;
    }

    // StateSetter 내부 클래스 (변경 없음)
    private final class StateSetter implements IdentityStateDsl {
        private void replaceLastState(StateType stateType) {
            List<AuthenticationFlowConfig> currentFlows = platformBuilder.getModifiableFlows();
            if (currentFlows.isEmpty()) {
                log.warn("AbstractFlowRegistrar.StateSetter: No flow to replace state for. State type '{}' will not be applied.", stateType);
                return;
            }
            int lastIndex = currentFlows.size() - 1;
            AuthenticationFlowConfig lastFlow = currentFlows.get(lastIndex);
            AuthenticationFlowConfig updatedFlow = lastFlow.withStateConfig(new StateConfig(stateType.name().toLowerCase(), stateType));
            currentFlows.set(lastIndex, updatedFlow);
            log.debug("AbstractFlowRegistrar.StateSetter: Set state for last flow (type: {}) to: {}",
                    lastFlow.getTypeName(), stateType);
        }

        @Override
        public IdentityAuthDsl session(Customizer<SessionStateConfigurer> customizer) {
            replaceLastState(StateType.SESSION);
            return AbstractFlowRegistrar.this;
        }

        @Override
        public IdentityAuthDsl jwt(Customizer<JwtStateConfigurer> customizer) {
            replaceLastState(StateType.JWT);
            return AbstractFlowRegistrar.this;
        }

        @Override
        public IdentityAuthDsl oauth2(Customizer<OAuth2StateConfigurer> customizer) {
            replaceLastState(StateType.OAUTH2);
            return AbstractFlowRegistrar.this;
        }
    }
}