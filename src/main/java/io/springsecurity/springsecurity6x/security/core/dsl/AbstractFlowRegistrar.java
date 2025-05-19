package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.BaseAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.AuthenticationFactorConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.MfaDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.MfaDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.factory.AuthMethodConfigurerFactory;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.feature.state.jwt.JwtStateConfigurer;
import io.springsecurity.springsecurity6x.security.core.feature.state.oauth2.OAuth2StateConfigurer;
import io.springsecurity.springsecurity6x.security.core.feature.state.session.SessionStateConfigurer;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.StateType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;

import java.util.List;
import java.util.Objects;

@Slf4j
public abstract class AbstractFlowRegistrar<H extends HttpSecurityBuilder<H>> implements IdentityAuthDsl {

    protected final PlatformConfig.Builder platformBuilder;
    private final StateSetter stateSetter;
    protected final ApplicationContext applicationContext;
    private final AuthMethodConfigurerFactory authMethodConfigurerFactory;
    protected final H httpSecurityBuilder;

    protected AbstractFlowRegistrar(PlatformConfig.Builder platformBuilder,
                                    ApplicationContext applicationContext,
                                    H httpSecurityBuilder) {
        this.platformBuilder = Objects.requireNonNull(platformBuilder, "platformBuilder cannot be null");
        this.applicationContext = Objects.requireNonNull(applicationContext, "applicationContext cannot be null");
        this.httpSecurityBuilder = Objects.requireNonNull(httpSecurityBuilder, "httpSecurityBuilder cannot be null");
        this.stateSetter = new StateSetter();
        this.authMethodConfigurerFactory = new AuthMethodConfigurerFactory(this.applicationContext);
    }

    /**
     * 단일 인증 흐름(Authentication Method)을 등록합니다.
     */
    protected <O extends AuthenticationProcessingOptions,
            A extends BaseAsepAttributes,
            S extends AuthenticationFactorConfigurer<O, A, S>> IdentityStateDsl registerAuthenticationMethod(
            AuthType authType,
            Customizer<S> configurerCustomizer,
            int defaultOrder,
            Class<S> configurerInterfaceType) { // Configurer 인터페이스 타입 명시적 전달

        // AuthMethodConfigurerFactory 에서 HttpSecurityBuilder를 사용하여 Configurer 생성 및 apply
        S configurer = authMethodConfigurerFactory.createFactorConfigurer(
                authType,
                this.httpSecurityBuilder, // 현재 Flow에 대한 HttpSecurityBuilder 전달
                configurerInterfaceType
        );

        Objects.requireNonNull(configurerCustomizer, "configurerCustomizer cannot be null").customize(configurer);
        O options = configurer.buildConcreteOptions(); // 옵션 빌드

        int actualOrder = (options.getOrder() != 0) ? options.getOrder() : defaultOrder;

        AuthenticationStepConfig stepConfig = new AuthenticationStepConfig();
        stepConfig.setType(authType.name().toLowerCase());
        stepConfig.getOptions().put("_options", options); // 옵션 객체 자체를 저장
        stepConfig.setOrder(actualOrder);

        AuthenticationFlowConfig.Builder flowBuilder = AuthenticationFlowConfig.builder(authType.name().toLowerCase())
                .stepConfigs(List.of(stepConfig))
                .stateConfig(null)
                .order(actualOrder);

        platformBuilder.addFlow(flowBuilder.build());
        log.info("AbstractFlowRegistrar: Registered authentication method: {}, Order: {}", authType, actualOrder);
        return this.stateSetter;
    }

    /**
     * 다중 스텝 인증 흐름(MFA)을 등록합니다.
     */
    protected IdentityStateDsl registerMultiStepFlow(
            Customizer<MfaDslConfigurer> customizer) { // BiFunction 제거

        MfaDslConfigurerImpl<H> mfaDslConfigurer =
                authMethodConfigurerFactory.createAndApplyMfaConfigurer(this.httpSecurityBuilder);

        Objects.requireNonNull(customizer, "mfa customizer cannot be null").customize(mfaDslConfigurer);
        AuthenticationFlowConfig mfaFlow = mfaDslConfigurer.build();

        platformBuilder.addFlow(mfaFlow);
        log.info("AbstractFlowRegistrar: Registered MFA flow. Order: {}. Steps: {}", mfaFlow.getOrder(), mfaFlow.getStepConfigs().size());
        return this.stateSetter;
    }

    private final class StateSetter implements IdentityStateDsl {
        private void replaceLastState(StateType stateType) {
            List<AuthenticationFlowConfig> currentFlows = platformBuilder.getModifiableFlows();
            if (currentFlows.isEmpty()) {
                log.warn("AbstractFlowRegistrar.StateSetter: No flow to replace state for. State type '{}' will not be applied.", stateType);
                return;
            }
            int lastIndex = currentFlows.size() - 1;
            AuthenticationFlowConfig lastFlow = currentFlows.get(lastIndex);
            // StateConfig 생성 시 StateType 전달
            AuthenticationFlowConfig updatedFlow = lastFlow.withStateConfig(new StateConfig(stateType.name().toLowerCase(), stateType));
            currentFlows.set(lastIndex, updatedFlow);
            log.debug("AbstractFlowRegistrar.StateSetter: Set state for last flow (type: {}, name: {}) to: {}",
                    lastFlow.getTypeName(), lastFlow.getTypeName(), stateType);
        }

        @Override
        public IdentityAuthDsl session(Customizer<SessionStateConfigurer> customizer) {
            // SessionStateConfigurer 인스턴스 생성 및 Customizer 적용
            // SessionStateConfigurer configurer = authMethodConfigurerFactory.createStateConfigurer(StateType.SESSION, this.httpSecurityBuilder, SessionStateConfigurer.class);
            // customizer.customize(configurer);
            // 실제 StateConfigurer 생성 및 적용 로직은 플랫폼의 구체적인 구현에 따름
            // 여기서는 상태 타입만 설정하고 실제 Configurer 적용은 다른 곳에서 이루어진다고 가정
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