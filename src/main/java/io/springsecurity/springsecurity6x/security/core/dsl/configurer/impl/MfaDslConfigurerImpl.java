package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.BaseAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.asep.dsl.MfaAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
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
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.exception.DslConfigurationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

import java.util.*;

@Slf4j
public final class MfaDslConfigurerImpl<H extends HttpSecurityBuilder<H>>
        extends AbstractHttpConfigurer<MfaDslConfigurerImpl<H>, H>
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
    private int order;

    private final List<AuthenticationStepConfig> configuredSteps = new ArrayList<>();
    private int currentStepOrderCounter = 1; // 0은 Primary Auth, Factor는 1부터 시작

    private PrimaryAuthDslConfigurerImpl<H> primaryAuthConfigurer; // PrimaryAuth 설정용


    public MfaDslConfigurerImpl(ApplicationContext applicationContext) {
        this.applicationContext = Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null");
        this.flowConfigBuilder = AuthenticationFlowConfig.builder(AuthType.MFA.name().toLowerCase()); // 내부에서 빌더 생성
        this.authMethodConfigurerFactory = new AuthMethodConfigurerFactory(this.applicationContext);
    }

    @Override
    public void init(H builder) throws Exception { // AbstractHttpConfigurer의 init 오버라이드
        this.primaryAuthConfigurer = new PrimaryAuthDslConfigurerImpl<>(this.applicationContext, builder);
        if (this.mfaFailureHandler == null) {
            // 플랫폼 기본 MfaFailureHandler 설정 등
        }
    }


    @Override
    public MfaDslConfigurerImpl<H> order(int order) {
        this.order = order;
        return this;
    }

    // primaryAuthentication()은 1차 인증 설정을 담당
    @Override
    public MfaDslConfigurerImpl<H> primaryAuthentication(Customizer<PrimaryAuthDslConfigurer> primaryAuthConfigCustomizer) {
        if (configuredSteps.stream().anyMatch(s -> s.getOrder() == 0)) {
            throw new IllegalStateException("Primary authentication has already been configured for this MFA flow via form() or rest() directly.");
        }
        Objects.requireNonNull(primaryAuthConfigCustomizer, "primaryAuthConfigCustomizer cannot be null");
        Assert.state(this.primaryAuthConfigurer != null, "MfaDslConfigurerImpl not properly initialized with HttpSecurityBuilder via init(). PrimaryAuthConfig cannot be created.");
        primaryAuthConfigCustomizer.customize(this.primaryAuthConfigurer);
        // 1차 인증 설정을 첫번째 스텝(order 0)으로 추가하는 로직은 build() 시점으로 이동
        return this;
    }

    // form()과 rest()는 이제 MFA의 1차 인증 "방식"을 설정하는 데 사용.
    // primaryAuthentication()을 대체하거나, 또는 primaryAuthentication() 내에서 호출될 수 있음.
    // MfaDslConfigurer 인터페이스 시그니처를 따름.
    @Override
    public MfaDslConfigurerImpl<H> form(Customizer<FormDslConfigurer> formConfigurerCustomizer) {
        if (primaryAuthConfigurer == null) {
            initBuilderIfNotSet(); // builder가 설정 안됐으면 여기서라도 설정 시도
        }
        this.primaryAuthConfigurer.formLogin(formConfigurerCustomizer);
        return this;
    }

    @Override
    public MfaDslConfigurerImpl<H> rest(Customizer<RestDslConfigurer> restConfigurerCustomizer) {
        if (primaryAuthConfigurer == null) {
            initBuilderIfNotSet();
        }
        this.primaryAuthConfigurer.restLogin(restConfigurerCustomizer);
        return this;
    }

    private void initBuilderIfNotSet() {
        if (getBuilder() == null) { // builder가 아직 설정되지 않았다면 (apply()가 호출되기 전 Customizer 에서 호출 시)
            log.warn("MfaDslConfigurerImpl: HttpSecurityBuilder not yet available. PrimaryAuth factors (form/rest) might not be fully initializable at this stage if they depend on the builder. Builder will be available in init/configure phases.");
            // 이 경우, primaryAuthConfigurer는 builder 없이 생성되거나, 또는 getBuilder() 시점에 예외 발생.
            // 안전하게는, MfaDslConfigurerImpl도 AbstractHttpConfigurer를 상속하고,
            // init(H builder)에서 HttpSecurityBuilder를 받아 primaryAuthConfigurer를 생성하는 것이 좋음.
            // (위에서 AbstractHttpConfigurer 상속으로 변경)
            // init(H)가 호출되면 this.primaryAuthConfigurer는 getBuilder()를 통해 H를 받음.
        }
    }


    private <O extends AuthenticationProcessingOptions,
            A extends BaseAsepAttributes,
            C extends AuthenticationFactorConfigurer<O, A, C>> // ASEP Attributes 타입 A 추가
    MfaDslConfigurerImpl<H> configureMfaFactor(
            AuthType authType,
            Customizer<C> factorConfigurerCustomizer,
            Class<C> configurerInterfaceType) { // 실제 인터페이스 타입 전달

        C configurer = authMethodConfigurerFactory.createFactorConfigurer(authType, getBuilder(), configurerInterfaceType);
        Objects.requireNonNull(factorConfigurerCustomizer, authType.name() + " customizer cannot be null").customize(configurer);
        O factorOptions = configurer.buildConcreteOptions();

        AuthenticationStepConfig factorStep = new AuthenticationStepConfig();
        factorStep.setType(authType.name().toLowerCase());
        factorStep.getOptions().put("_options", factorOptions);
        factorStep.setOrder(currentStepOrderCounter++); // 1차 인증이 0번, Factor는 1번부터
        this.configuredSteps.add(factorStep);
        log.debug("ASEP: Added MFA factor step: {} with order {}", factorStep.getType(), factorStep.getOrder());
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
        log.warn("MfaDslConfigurerImpl: RecoveryCodeDslConfigurer integration needs specific implementation based on its options and AuthType.");
        return this;
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
    public MfaDslConfigurerImpl<H> asep(Customizer<MfaAsepAttributes> mfaAsepAttributesCustomizer){
        H builder = getBuilder();
        MfaAsepAttributes attributes = builder.getSharedObject(MfaAsepAttributes.class);
        if (attributes == null) {
            attributes = new MfaAsepAttributes();
        }
        if (mfaAsepAttributesCustomizer != null) {
            mfaAsepAttributesCustomizer.customize(attributes);
        }
        builder.setSharedObject(MfaAsepAttributes.class, attributes);
        log.debug("ASEP: MfaAsepAttributes (global for MFA flow) stored/updated in sharedObjects for builder hash: {}",
                System.identityHashCode(builder));
        return this;
    }


    @Override
    public AuthenticationFlowConfig build() {
        // 1차 인증 설정 처리 (primaryAuthConfigurer가 설정된 경우)
        PrimaryAuthenticationOptions primaryAuthOptionsForFlow = null;
        if (this.primaryAuthConfigurer != null) {
            try {
                primaryAuthOptionsForFlow = this.primaryAuthConfigurer.buildOptions();
                AuthenticationProcessingOptions firstStepAuthOptions = primaryAuthOptionsForFlow.getFormOptions() != null ?
                        primaryAuthOptionsForFlow.getFormOptions() :
                        primaryAuthOptionsForFlow.getRestOptions();
                AuthType firstStepAuthType = primaryAuthOptionsForFlow.getFormOptions() != null ? AuthType.FORM : AuthType.REST;

                // configuredSteps 에서 order 0이 이미 있는지 확인 (form/rest 직접 호출 대비)
                if (configuredSteps.stream().noneMatch(s -> s.getOrder() == 0)) {
                    AuthenticationStepConfig primaryAuthStep = new AuthenticationStepConfig();
                    primaryAuthStep.setType(firstStepAuthType.name().toLowerCase());
                    primaryAuthStep.getOptions().put("_options", firstStepAuthOptions);
                    primaryAuthStep.setOrder(0); // 1차 인증은 항상 order 0
                    configuredSteps.add(primaryAuthStep);
                    log.debug("MFA Flow: Added primary authentication step (type: {}) from primaryAuthentication() DSL.", firstStepAuthType);
                } else {
                    log.warn("MFA Flow: Primary authentication (order 0) was already added via direct form()/rest() call. " +
                            "The configuration from primaryAuthentication() DSL might be ignored or cause conflict if direct calls also set order 0.");
                    // 정책: primaryAuthentication()이 명시적으로 호출되면, 직접 호출된 form/rest는 무시하거나 에러.
                    // 또는, direct form()/rest()를 order 0으로 설정하지 못하도록 강제.
                    // 현재는 configuredSteps에 이미 order 0이 있으면 primaryAuthentication()은 덮어쓰지 않음.
                    // 이는 primaryAuthentication() 보다 form()/rest() 직접 호출이 우선된다는 의미.
                    // -> 수정: primaryAuthentication()을 더 우선시 하거나, 중복 설정 시 예외 발생.
                    // -> 여기서는 기존 로직(addPrimaryAuthStep)을 사용하지 않고, build 시점에 처리.
                }
            } catch (DslConfigurationException e) {
                log.error("MFA primary authentication configuration error.", e);
                throw e;
            }
        }

        Assert.isTrue(!configuredSteps.isEmpty(), "MFA flow must have at least one authentication step.");
        configuredSteps.sort(Comparator.comparingInt(AuthenticationStepConfig::getOrder));

        AuthenticationStepConfig firstConfiguredStep = configuredSteps.get(0);
        Assert.isTrue(firstConfiguredStep.getOrder() == 0 &&
                        (AuthType.FORM.name().equalsIgnoreCase(firstConfiguredStep.getType()) || AuthType.REST.name().equalsIgnoreCase(firstConfiguredStep.getType())),
                "MFA flow must start with a FORM or REST primary authentication step (order 0).");
        Assert.isTrue(configuredSteps.size() > 1, "MFA flow must have at least one secondary authentication factor (e.g., OTT, Passkey).");

        // primaryAuthOptionsForFlow가 build() 초기에 설정되지 않았다면, configuredSteps의 첫번째로 재구성
        if (primaryAuthOptionsForFlow == null) {
            Object firstStepOptionsObject = firstConfiguredStep.getOptions().get("_options");
            if (firstStepOptionsObject instanceof FormOptions fo) { // 패턴 변수 사용
                primaryAuthOptionsForFlow = PrimaryAuthenticationOptions.builder().formOptions(fo).build();
            } else if (firstStepOptionsObject instanceof RestOptions ro) {
                primaryAuthOptionsForFlow = PrimaryAuthenticationOptions.builder().restOptions(ro).build();
            } else {
                throw new DslConfigurationException("Primary authentication step (order 0) in MFA flow has incompatible options type: " +
                        (firstStepOptionsObject != null ? firstStepOptionsObject.getClass().getName() : "null"));
            }
        }


        Map<AuthType, AuthenticationProcessingOptions> factorOptionsMap = new HashMap<>();
        for (int i = 1; i < configuredSteps.size(); i++) { // 0번은 Primary, 1번부터 Factor
            AuthenticationStepConfig step = configuredSteps.get(i);
            Object stepOptionsObject = step.getOptions().get("_options");
            if (!(stepOptionsObject instanceof AuthenticationProcessingOptions factorOption)) { // 패턴 변수 사용
                throw new DslConfigurationException("Options for MFA factor step '" + step.getType() +
                        "' are not of type AuthenticationProcessingOptions.");
            }
            try {
                AuthType factorType = AuthType.valueOf(step.getType().toUpperCase());
                factorOptionsMap.put(factorType, factorOption);
            } catch (IllegalArgumentException e) {
                throw new DslConfigurationException("Invalid AuthType string for MFA factor stepConfig: " + step.getType(), e);
            }
        }

        flowConfigBuilder
                .typeName(AuthType.MFA.name().toLowerCase())
                .order(this.order)
                .primaryAuthenticationOptions(primaryAuthOptionsForFlow)
                .stepConfigs(Collections.unmodifiableList(new ArrayList<>(this.configuredSteps)))
                .mfaPolicyProvider(this.policyProvider)
                .mfaContinuationHandler(this.continuationHandler)
                .mfaFailureHandler(this.mfaFailureHandler)
                .finalSuccessHandler(this.finalSuccessHandler)
                .registeredFactorOptions(Collections.unmodifiableMap(factorOptionsMap)) // 불변 맵
                .defaultRetryPolicy(this.defaultRetryPolicy)
                .defaultAdaptiveConfig(this.defaultAdaptiveConfig)
                .defaultDeviceTrustEnabled(this.defaultDeviceTrustEnabled);

        log.info("MFA Flow Config built with {} steps. Primary Auth: {}, Factors: {}",
                configuredSteps.size(),
                primaryAuthOptionsForFlow != null ? (primaryAuthOptionsForFlow.getFormOptions() != null ? "FORM" : "REST") : "NOT_CONFIGURED_VIA_PRIMARY_DSL",
                factorOptionsMap.keySet());
        return flowConfigBuilder.build();
    }

    @Override
    public void configure(H builder) throws Exception {
        builder.setSharedObject(AuthenticationFlowConfig.class, build()); // 빌드된 FlowConfig 공유
        log.debug("MfaDslConfigurerImpl: Configured HttpSecurityBuilder by sharing built AuthenticationFlowConfig. " +
                "Actual MFA filters should be applied by a dedicated MfaAuthenticationFeature using this config.");
    }
}


