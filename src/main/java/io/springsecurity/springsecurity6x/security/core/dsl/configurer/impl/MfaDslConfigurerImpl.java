package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.BaseAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.asep.dsl.MfaAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.*;
import io.springsecurity.springsecurity6x.security.core.dsl.factory.AuthMethodConfigurerFactory;
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
import io.springsecurity.springsecurity6x.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.exception.DslConfigurationException;
import io.springsecurity.springsecurity6x.security.handler.PlatformAuthenticationFailureHandler;
import io.springsecurity.springsecurity6x.security.handler.PlatformAuthenticationSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
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
    private PlatformAuthenticationFailureHandler mfaFailureHandler;
    private AuthenticationSuccessHandler finalSuccessHandler;
    private RetryPolicy defaultRetryPolicy;
    private AdaptiveConfig defaultAdaptiveConfig;
    private boolean defaultDeviceTrustEnabled = false;
    private int order = 200;

    private final List<AuthenticationStepConfig> configuredSteps = new ArrayList<>();
    private int currentStepOrderCounter = 1;

    private final PrimaryAuthDslConfigurerImpl<H> primaryAuthConfigurer;
    private MfaAsepAttributes mfaAsepAttributes;

    private final String mfaFlowTypeName = AuthType.MFA.name().toLowerCase(); // MFA 플로우 식별용 이름

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
        throw new UnsupportedOperationException("Use .primaryAuthentication(primary -> primary.formLogin(...)) for MFA flow's primary auth.");
    }

    @Override
    public MfaDslConfigurerImpl<H> rest(Customizer<RestDslConfigurer> restConfigurerCustomizer) {
        throw new UnsupportedOperationException("Use .primaryAuthentication(primary -> primary.restLogin(...)) for MFA flow's primary auth.");
    }

    /*@Override
    public MfaDslConfigurerImpl<H> form(Customizer<FormDslConfigurer> formConfigurerCustomizer) {
        this.primaryAuthConfigurer.formLogin(formConfigurerCustomizer);
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> rest(Customizer<RestDslConfigurer> restConfigurerCustomizer) {
        this.primaryAuthConfigurer.restLogin(restConfigurerCustomizer);
        return this;
    }*/

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

        int stepOrder = currentStepOrderCounter++;
        AuthenticationStepConfig factorStep = new AuthenticationStepConfig(this.mfaFlowTypeName, authType.name(), stepOrder, false);
        factorStep.getOptions().put("_options", factorOptions);
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
    public MfaDslConfigurerImpl<H> mfaFailureHandler(PlatformAuthenticationFailureHandler  failureHandler) {
        this.mfaFailureHandler = failureHandler;
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> policyProvider(MfaPolicyProvider policyProvider) {
        this.policyProvider = policyProvider;
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> mfaSuccessHandler(PlatformAuthenticationSuccessHandler handler) {
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

        if (this.primaryAuthConfigurer.getFormLoginCustomizer() != null || this.primaryAuthConfigurer.getRestLoginCustomizer() != null) {
            primaryAuthOptionsForFlow = this.primaryAuthConfigurer.buildOptions();
            AuthenticationProcessingOptions primaryConcreteOptions = primaryAuthOptionsForFlow.isFormLogin() ?
                    primaryAuthOptionsForFlow.getFormOptions() : primaryAuthOptionsForFlow.getRestOptions();
            AuthType primaryAuthType = primaryAuthOptionsForFlow.isFormLogin() ? AuthType.FORM : AuthType.MFA_REST;

            // 기존 order 0 스텝 제거 (중복 방지)
            configuredSteps.removeIf(s -> s.getOrder() == 0);

            // 1차 인증 스텝 생성 및 configuredSteps 리스트의 맨 앞에 추가
            AuthenticationStepConfig primaryAuthStep = new AuthenticationStepConfig(this.mfaFlowTypeName, primaryAuthType.name(), 0, true);
            primaryAuthStep.getOptions().put("_options", primaryConcreteOptions);
            configuredSteps.addFirst(primaryAuthStep);
            log.debug("MFA Flow [{}]: Added primary authentication step (id='{}', type: {}) from primaryAuthentication() DSL.",
                    this.mfaFlowTypeName, primaryAuthStep.getStepId(), primaryAuthType);
        } else {
            // primaryAuthentication() DSL이 호출되지 않은 경우, 첫번째로 추가된 step (order 0)이 1차 인증으로 간주되어야 함.
            // 또는, primaryAuthentication()을 필수로 만들 수 있음.
            // 여기서는 configuredSteps의 첫번째가 1차 인증이라고 가정 (만약 있다면).
            if (configuredSteps.isEmpty() || configuredSteps.getFirst().getOrder() != 0) {
                throw new DslConfigurationException("MFA flow [" + this.mfaFlowTypeName + "] must have a primary authentication step (order 0) or use .primaryAuthentication() DSL.");
            }
            Object firstStepOptionsObj = configuredSteps.getFirst().getOptions().get("_options");
            if (firstStepOptionsObj instanceof FormOptions fo) {
                primaryAuthOptionsForFlow = PrimaryAuthenticationOptions.builder().formOptions(fo).loginProcessingUrl(fo.getLoginProcessingUrl()).build();
            } else if (firstStepOptionsObj instanceof RestOptions ro) {
                primaryAuthOptionsForFlow = PrimaryAuthenticationOptions.builder().restOptions(ro).loginProcessingUrl(ro.getLoginProcessingUrl()).build();
            } else {
                throw new DslConfigurationException("Could not determine PrimaryAuthenticationOptions from the first step of MFA flow ["+ this.mfaFlowTypeName +"].");
            }
        }

        Assert.isTrue(!configuredSteps.isEmpty(), "MFA flow ["+ this.mfaFlowTypeName +"] must have at least one authentication step (primary).");
        configuredSteps.sort(Comparator.comparingInt(AuthenticationStepConfig::getOrder));

        AuthenticationStepConfig firstConfiguredStep = configuredSteps.getFirst();
        Assert.isTrue(firstConfiguredStep.getOrder() == 0, "MFA flow's first step must have order 0.");
        Assert.isTrue(AuthType.FORM.name().equalsIgnoreCase(firstConfiguredStep.getType()) || AuthType.MFA_REST.name().equalsIgnoreCase(firstConfiguredStep.getType()),
                "MFA flow must start with a FORM or REST primary authentication step. Current first step: " + firstConfiguredStep.getType());
        Assert.isTrue(configuredSteps.size() > 1, "MFA flow must have at least one secondary authentication factor.");

        if (primaryAuthOptionsForFlow == null) {
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


