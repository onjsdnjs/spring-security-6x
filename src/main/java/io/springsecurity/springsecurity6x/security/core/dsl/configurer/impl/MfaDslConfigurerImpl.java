package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.BaseAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.asep.dsl.MfaAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.*;
import io.springsecurity.springsecurity6x.security.core.dsl.factory.AuthMethodConfigurerFactory;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AbstractOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.AdaptiveConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.AdaptiveDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.AdaptiveDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.RetryPolicyDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.RetryPolicyDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaContinuationHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.exception.DslConfigurationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

import java.util.*;

@Slf4j
public final class MfaDslConfigurerImpl<H extends HttpSecurityBuilder<H>>
        implements MfaDslConfigurer {

    private final AuthenticationFlowConfig.Builder flowConfigBuilder;
    private final AuthMethodConfigurerFactory authMethodConfigurerFactory;
    private final ApplicationContext applicationContext;

    private MfaPolicyProvider policyProvider;
    private MfaContinuationHandler continuationHandler;
    private MfaFailureHandler mfaFailureHandler;
    private AuthenticationSuccessHandler finalSuccessHandler;
    private RetryPolicy defaultRetryPolicy;
    private AdaptiveConfig defaultAdaptiveConfig;
    private boolean defaultDeviceTrustEnabled = false;
    private int order = 200;

    private final List<AuthenticationStepConfig> configuredSteps = new ArrayList<>();
    private int currentStepOrderCounter = 1;

    private final PrimaryAuthDslConfigurerImpl<H> primaryAuthConfigurer;
    private MfaAsepAttributes mfaAsepAttributes;

    public MfaDslConfigurerImpl(ApplicationContext applicationContext) {
        this.applicationContext = Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null");
        this.flowConfigBuilder = AuthenticationFlowConfig.builder(AuthType.MFA.name().toLowerCase());
        this.authMethodConfigurerFactory = new AuthMethodConfigurerFactory(this.applicationContext);
        this.primaryAuthConfigurer = new PrimaryAuthDslConfigurerImpl<>(this.applicationContext);
    }

    @Override
    public MfaDslConfigurerImpl<H> order(int order) {
        this.order = order;
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> primaryAuthentication(Customizer<PrimaryAuthDslConfigurer> primaryAuthConfigCustomizer) {
        Objects.requireNonNull(primaryAuthConfigCustomizer, "primaryAuthConfigCustomizer cannot be null");
        primaryAuthConfigCustomizer.customize(this.primaryAuthConfigurer);
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> form(Customizer<FormDslConfigurer> formConfigurerCustomizer) {
        this.primaryAuthConfigurer.formLogin(formConfigurerCustomizer);
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> rest(Customizer<RestDslConfigurer> restConfigurerCustomizer) {
        this.primaryAuthConfigurer.restLogin(restConfigurerCustomizer);
        return this;
    }

    private <O_FACTOR extends AuthenticationProcessingOptions,
            A_FACTOR extends BaseAsepAttributes,
            C_FACTOR extends AuthenticationFactorConfigurer<O_FACTOR, A_FACTOR, C_FACTOR>> MfaDslConfigurerImpl<H> configureMfaFactor(
            AuthType authType,
            Customizer<C_FACTOR> factorConfigurerCustomizer,
            Class<C_FACTOR> configurerInterfaceType) {

        C_FACTOR configurer = authMethodConfigurerFactory.createFactorConfigurer(authType, configurerInterfaceType);

        if (configurer instanceof AbstractOptionsBuilderConfigurer) {
            ((AbstractOptionsBuilderConfigurer<?, O_FACTOR, ?, C_FACTOR>) configurer).setApplicationContext(this.applicationContext);
        }

        Objects.requireNonNull(factorConfigurerCustomizer, authType.name() + " customizer cannot be null").customize(configurer);
        O_FACTOR factorOptions = configurer.buildConcreteOptions();

        AuthenticationStepConfig factorStep = new AuthenticationStepConfig();
        factorStep.setType(authType.name().toLowerCase());
        factorStep.getOptions().put("_options", factorOptions);
        factorStep.setOrder(currentStepOrderCounter++);
        this.configuredSteps.add(factorStep);
        log.debug("MFA Flow: Added factor step: {} with order {}", factorStep.getType(), factorStep.getOrder());
        return this;
    }


    @Override
    public MfaDslConfigurerImpl<H> ott(Customizer<OttDslConfigurer> ottConfigurerCustomizer) {
        return configureMfaFactor(AuthType.OTT, ottConfigurerCustomizer, OttDslConfigurer.class);
    }

    @Override
    public MfaDslConfigurerImpl<H> passkey(Customizer<PasskeyDslConfigurer> passkeyConfigurerCustomizer) {
        return configureMfaFactor(AuthType.PASSKEY, passkeyConfigurerCustomizer, PasskeyDslConfigurer.class);
    }

    @Override
    public MfaDslConfigurerImpl<H> recoveryFlow(Customizer<RecoveryCodeDslConfigurer> recoveryConfigurerCustomizer) {
        log.debug("Configuring MFA recovery flow step.");
        // RecoveryCodeDslConfigurer는 AuthenticationFactorConfigurer<RecoveryCodeOptions, ..., RecoveryCodeDslConfigurer>를 구현해야 함
        // RecoveryCodeOptions가 AbstractOptions를 상속하도록 수정 필요
        return configureMfaFactor(AuthType.RECOVERY_CODE, recoveryConfigurerCustomizer, RecoveryCodeDslConfigurer.class);
    }


    @Override
    public MfaDslConfigurerImpl<H> mfaContinuationHandler(MfaContinuationHandler continuationHandler) {
        this.continuationHandler = continuationHandler;
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> mfaFailureHandler(MfaFailureHandler failureHandler) {
        this.mfaFailureHandler = failureHandler;
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> policyProvider(MfaPolicyProvider policyProvider) {
        this.policyProvider = policyProvider;
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> finalSuccessHandler(AuthenticationSuccessHandler handler) {
        this.finalSuccessHandler = handler;
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> defaultRetryPolicy(Customizer<RetryPolicyDslConfigurer> c) {
        RetryPolicyDslConfigurerImpl configurer = new RetryPolicyDslConfigurerImpl();
        c.customize(configurer);
        this.defaultRetryPolicy = configurer.build();
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> defaultAdaptivePolicy(Customizer<AdaptiveDslConfigurer> c) {
        AdaptiveDslConfigurerImpl configurer = new AdaptiveDslConfigurerImpl();
        c.customize(configurer);
        this.defaultAdaptiveConfig = configurer.build();
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> defaultDeviceTrustEnabled(boolean enable) {
        this.defaultDeviceTrustEnabled = enable;
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> asep(Customizer<MfaAsepAttributes> mfaAsepAttributesCustomizer) {
        this.mfaAsepAttributes = new MfaAsepAttributes();
        if (mfaAsepAttributesCustomizer != null) {
            mfaAsepAttributesCustomizer.customize(this.mfaAsepAttributes);
        }
        log.debug("ASEP: MfaAsepAttributes (global for MFA flow) configured.");
        return this;
    }


    @Override
    public AuthenticationFlowConfig build() {
        PrimaryAuthenticationOptions primaryAuthOptionsForFlow = null;

        // primaryAuthConfigurer의 getter를 통해 Customizer 설정 여부 확인 (이전 답변에서 getter 추가됨)
        if (this.primaryAuthConfigurer != null &&
                (this.primaryAuthConfigurer.getFormLoginCustomizer() != null || this.primaryAuthConfigurer.getRestLoginCustomizer() != null)) {
            try {
                primaryAuthOptionsForFlow = this.primaryAuthConfigurer.buildOptions();

                AuthenticationProcessingOptions firstStepAuthOptions = primaryAuthOptionsForFlow.getFormOptions() != null ?
                        primaryAuthOptionsForFlow.getFormOptions() :
                        primaryAuthOptionsForFlow.getRestOptions();
                // PrimaryAuthenticationOptions에 isFormLogin()과 같은 편의 메서드가 있다면 사용
                AuthType firstStepAuthType = primaryAuthOptionsForFlow.isFormLogin() ? AuthType.FORM : AuthType.REST;

                configuredSteps.removeIf(s -> s.getOrder() == 0); // 기존 0번 스텝이 있다면 제거

                AuthenticationStepConfig primaryAuthStep = new AuthenticationStepConfig();
                primaryAuthStep.setType(firstStepAuthType.name().toLowerCase());
                primaryAuthStep.getOptions().put("_options", firstStepAuthOptions);
                primaryAuthStep.setOrder(0);
                configuredSteps.add(0, primaryAuthStep);
                log.debug("MFA Flow: Added primary authentication step (type: {}) from primaryAuthentication() DSL.", firstStepAuthType);

            } catch (Exception e) {
                log.error("MFA primary authentication options building failed: {}", e.getMessage(), e);
                throw new DslConfigurationException("Failed to build primary authentication options for MFA flow.", e);
            }
        }

        Assert.isTrue(!configuredSteps.isEmpty(), "MFA flow must have at least one authentication step (primary).");
        configuredSteps.sort(Comparator.comparingInt(AuthenticationStepConfig::getOrder));

        AuthenticationStepConfig firstConfiguredStep = configuredSteps.get(0);
        Assert.isTrue(firstConfiguredStep.getOrder() == 0, "MFA flow's first step must have order 0.");
        Assert.isTrue(AuthType.FORM.name().equalsIgnoreCase(firstConfiguredStep.getType()) || AuthType.REST.name().equalsIgnoreCase(firstConfiguredStep.getType()),
                "MFA flow must start with a FORM or REST primary authentication step. Current first step: " + firstConfiguredStep.getType());
        Assert.isTrue(configuredSteps.size() > 1, "MFA flow must have at least one secondary authentication factor.");

        if (primaryAuthOptionsForFlow == null) { // primaryAuthentication() DSL이 명시적으로 사용되지 않은 경우
            Object firstStepRawOptions = firstConfiguredStep.getOptions().get("_options");
            if (firstStepRawOptions instanceof FormOptions fo) {
                primaryAuthOptionsForFlow = PrimaryAuthenticationOptions.builder().formOptions(fo).loginProcessingUrl(fo.getLoginProcessingUrl()).build();
            } else if (firstStepRawOptions instanceof RestOptions ro) {
                primaryAuthOptionsForFlow = PrimaryAuthenticationOptions.builder().restOptions(ro).loginProcessingUrl(ro.getLoginProcessingUrl()).build();
            } else {
                throw new DslConfigurationException("Could not determine PrimaryAuthenticationOptions from the first step of MFA flow. Step options type: " +
                        (firstStepRawOptions != null ? firstStepRawOptions.getClass().getName() : "null"));
            }
        }

        Map<AuthType, AuthenticationProcessingOptions> factorOptionsMap = new HashMap<>();
        for (int i = 1; i < configuredSteps.size(); i++) {
            AuthenticationStepConfig step = configuredSteps.get(i);
            Object stepOptionsObject = step.getOptions().get("_options");
            if (!(stepOptionsObject instanceof AuthenticationProcessingOptions factorOption)) { // 패턴 변수 바인딩
                throw new DslConfigurationException("Options for MFA factor step '" + step.getType() +
                        "' are not of type AuthenticationProcessingOptions. Actual: " + (stepOptionsObject != null ? stepOptionsObject.getClass().getName() : "null"));
            }
            try {
                AuthType factorType = AuthType.valueOf(step.getType().toUpperCase());
                factorOptionsMap.put(factorType, factorOption);
            } catch (IllegalArgumentException e) {
                throw new DslConfigurationException("Invalid AuthType string for MFA factor stepConfig: " + step.getType(), e);
            }
        }

        return flowConfigBuilder
                .typeName(AuthType.MFA.name().toLowerCase())
                .order(this.order)
                .primaryAuthenticationOptions(primaryAuthOptionsForFlow)
                .stepConfigs(Collections.unmodifiableList(new ArrayList<>(this.configuredSteps)))
                .mfaPolicyProvider(this.policyProvider)
                .mfaContinuationHandler(this.continuationHandler)
                .mfaFailureHandler(this.mfaFailureHandler)
                .finalSuccessHandler(this.finalSuccessHandler)
                .registeredFactorOptions(Collections.unmodifiableMap(factorOptionsMap))
                .defaultRetryPolicy(this.defaultRetryPolicy)
                .defaultAdaptiveConfig(this.defaultAdaptiveConfig)
                .defaultDeviceTrustEnabled(this.defaultDeviceTrustEnabled)
                .mfaAsepAttributes(this.mfaAsepAttributes)
                .build();
    }
}


