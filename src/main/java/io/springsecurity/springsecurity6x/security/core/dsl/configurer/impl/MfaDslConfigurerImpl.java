package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.*;
import io.springsecurity.springsecurity6x.security.core.dsl.factory.AuthMethodConfigurerFactory;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.AdaptiveConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.AdaptiveDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.RetryPolicyDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.RetryPolicyDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaContinuationHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.exception.DslConfigurationException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

import java.util.*;

public class MfaDslConfigurerImpl implements MfaDslConfigurer {

    private final AuthenticationFlowConfig.Builder flowConfigBuilder;
    private final AuthMethodConfigurerFactory authMethodConfigurerFactory;
    // private PrimaryAuthenticationOptions primaryAuthenticationOptions; // 직접 사용 대신 stepConfigs에 포함

    private MfaPolicyProvider policyProvider;
    private MfaContinuationHandler continuationHandler;
    private MfaFailureHandler failureHandler;
    private AuthenticationSuccessHandler finalSuccessHandler;
    // private final Map<AuthType, AuthenticationProcessingOptions> registeredFactorOptionsMap = new HashMap<>(); // stepConfigs로 통합 관리
    private RetryPolicy defaultRetryPolicy;
    private AdaptiveConfig defaultAdaptiveConfig;
    private boolean defaultDeviceTrustEnabled = false;
    private int order;

    // configuredSteps가 이제 1차 인증을 포함한 모든 단계를 순서대로 가짐
    private final List<AuthenticationStepConfig> configuredSteps = new ArrayList<>();
    private int currentStepOrderCounter = 0; // 스텝 순서 자동 부여용

    public MfaDslConfigurerImpl(AuthenticationFlowConfig.Builder flowConfigBuilder, ApplicationContext applicationContext) {
        this.flowConfigBuilder = flowConfigBuilder;
        this.authMethodConfigurerFactory = new AuthMethodConfigurerFactory(applicationContext);
    }

    @Override
    public MfaDslConfigurer order(int order) {
        this.order = order;
        return this;
    }

    // primaryAuthentication 메서드는 제거하거나 내부적으로 form/rest를 호출하도록 변경.
    // 여기서는 form/rest를 직접 사용하도록 유도.

    @Override
    public MfaDslConfigurer form(Customizer<FormDslConfigurer> formConfigurerCustomizer) {
        // 1차 인증으로 FORM 설정
        FormDslConfigurer configurer = authMethodConfigurerFactory.createConfigurer(AuthType.FORM);
        formConfigurerCustomizer.customize(configurer);
        FormOptions formOptions = configurer.buildConcreteOptions();

        AuthenticationStepConfig primaryAuthStep = new AuthenticationStepConfig();
        primaryAuthStep.setType(AuthType.FORM.name().toLowerCase());
        primaryAuthStep.getOptions().put("_options", formOptions);
        primaryAuthStep.setOrder(assignOrderAndIncrement()); // 1차 인증은 항상 첫 번째 (order 0)

        // 이미 1차 인증 스텝이 있는지 확인하고, 있다면 예외 또는 덮어쓰기 정책 필요
        if (configuredSteps.stream().anyMatch(s -> s.getOrder() == 0)) {
            throw new IllegalStateException("Primary authentication (form/rest) has already been configured for this MFA flow.");
        }
        configuredSteps.add(primaryAuthStep);
        // flowConfigBuilder.primaryAuthenticationOptions(...)는 더 이상 직접 설정하지 않음.
        return this;
    }

    @Override
    public MfaDslConfigurer rest(Customizer<RestDslConfigurer> restConfigurerCustomizer) {
        // 1차 인증으로 REST 설정
        RestDslConfigurer configurer = authMethodConfigurerFactory.createConfigurer(AuthType.REST);
        restConfigurerCustomizer.customize(configurer);
        RestOptions restOptions = configurer.buildConcreteOptions();

        AuthenticationStepConfig primaryAuthStep = new AuthenticationStepConfig();
        primaryAuthStep.setType(AuthType.REST.name().toLowerCase());
        primaryAuthStep.getOptions().put("_options", restOptions);
        primaryAuthStep.setOrder(assignOrderAndIncrement()); // 1차 인증은 항상 첫 번째 (order 0)

        if (configuredSteps.stream().anyMatch(s -> s.getOrder() == 0)) {
            throw new IllegalStateException("Primary authentication (form/rest) has already been configured for this MFA flow.");
        }
        configuredSteps.add(primaryAuthStep);
        return this;
    }

    private int assignOrderAndIncrement() {
        return currentStepOrderCounter++;
    }


    private <O extends AuthenticationProcessingOptions, C extends AuthenticationFactorConfigurer<O, C>>
    MfaDslConfigurer configureMfaFactor(
            AuthType authType,
            Customizer<C> factorConfigurerCustomizer) {

        C configurer = authMethodConfigurerFactory.createConfigurer(authType);
        factorConfigurerCustomizer.customize(configurer);

        O factorOptions = configurer.buildConcreteOptions();
        // this.registeredFactorOptionsMap.put(authType, factorOptions); // 더 이상 사용 안 함

        AuthenticationStepConfig factorStep = new AuthenticationStepConfig();
        factorStep.setType(authType.name().toLowerCase());
        factorStep.getOptions().put("_options", factorOptions);
        factorStep.setOrder(assignOrderAndIncrement()); // 1차 인증 이후 순서대로 order 부여
        this.configuredSteps.add(factorStep);
        return this;
    }

    @Override
    public MfaDslConfigurer ott(Customizer<OttDslConfigurer> ottConfigurerCustomizer) {
        return configureMfaFactor(AuthType.OTT, ottConfigurerCustomizer);
    }

    @Override
    public MfaDslConfigurer passkey(Customizer<PasskeyDslConfigurer> passkeyConfigurerCustomizer) {
        return configureMfaFactor(AuthType.PASSKEY, passkeyConfigurerCustomizer);
    }

    @Override
    public MfaDslConfigurer recoveryFlow(Customizer<RecoveryCodeDslConfigurer> recoveryConfigurerCustomizer) {
        return configureMfaFactor(AuthType.RECOVERY_CODE, recoveryConfigurerCustomizer);
    }


    @Override
    public MfaDslConfigurer mfaContinuationHandler(MfaContinuationHandler continuationHandler) {
        this.continuationHandler = continuationHandler;
        return this;
    }

    @Override
    public MfaDslConfigurer mfaFailureHandler(MfaFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return this;
    }

    @Override
    public MfaDslConfigurer policyProvider(MfaPolicyProvider policyProvider) {
        this.policyProvider = policyProvider;
        return this;
    }

    @Override
    public MfaDslConfigurer finalSuccessHandler(AuthenticationSuccessHandler handler) {
        this.finalSuccessHandler = handler;
        return this;
    }

    @Override
    public MfaDslConfigurer defaultRetryPolicy(Customizer<RetryPolicyDslConfigurer> c) {
        RetryPolicyDslConfigurerImpl configurer = new RetryPolicyDslConfigurerImpl();
        c.customize(configurer);
        this.defaultRetryPolicy = configurer.build();
        return this;
    }

    @Override
    public MfaDslConfigurer defaultAdaptivePolicy(Customizer<io.springsecurity.springsecurity6x.security.core.mfa.configurer.AdaptiveDslConfigurer> c) {
        AdaptiveDslConfigurerImpl configurer = new AdaptiveDslConfigurerImpl();
        c.customize(configurer);
        this.defaultAdaptiveConfig = configurer.build();
        return this;
    }

    @Override
    public MfaDslConfigurer defaultDeviceTrustEnabled(boolean enable) {
        this.defaultDeviceTrustEnabled = enable;
        return this;
    }

    // primaryAuthentication() 메서드는 사용하지 않으므로 주석 처리 또는 삭제
    @Override
    public MfaDslConfigurer primaryAuthentication(Customizer<PrimaryAuthDslConfigurer> primaryAuthConfig) {
        // 이 메서드 대신 form() 또는 rest()를 직접 사용하도록 유도.
        // 만약 이 메서드를 유지하려면, 내부적으로 form() 또는 rest()를 호출하도록 구현 변경 필요.
        // 예:
        // PrimaryAuthDslConfigurerImpl primaryConfigurer = new PrimaryAuthDslConfigurerImpl();
        // primaryAuthConfig.customize(primaryConfigurer);
        // PrimaryAuthenticationOptions opts = primaryConfigurer.buildOptions();
        // if (opts.isFormLogin()) {
        //     this.form(form -> form.getOptionsBuilder().loginPage(opts.getFormOptions().getLoginPage()) /* ...etc... */);
        // } else if (opts.isRestLogin()) {
        //     this.rest(rest -> rest.getOptionsBuilder().loginProcessingUrl(opts.getRestOptions().getLoginProcessingUrl()) /* ...etc... */);
        // }
        throw new UnsupportedOperationException("primaryAuthentication() is deprecated for MFA flow. Use form() or rest() directly within the MFA block.");
    }


    @Override
    public AuthenticationFlowConfig build() {
        // 1차 인증 스텝이 configuredSteps의 첫 번째로 설정되었는지 확인
        Assert.isTrue(!configuredSteps.isEmpty() && configuredSteps.getFirst().getOrder() == 0 &&
                        (AuthType.FORM.name().equalsIgnoreCase(configuredSteps.getFirst().getType()) || AuthType.REST.name().equalsIgnoreCase(configuredSteps.get(0).getType())),
                "MFA flow must start with a FORM or REST primary authentication step.");
        Assert.isTrue(configuredSteps.size() > 1, "MFA flow must have at least one secondary authentication factor (e.g., OTT, Passkey) configured after primary authentication.");

        // configuredSteps를 order 기준으로 정렬 (이미 순서대로 추가되었지만, 안전장치)
        configuredSteps.sort(Comparator.comparingInt(AuthenticationStepConfig::getOrder));

        // registeredFactorOptionsMap 생성 (2차 인증 요소들만 포함)
        Map<AuthType, AuthenticationProcessingOptions> factorOptionsMap = new HashMap<>();
        for (int i = 1; i < configuredSteps.size(); i++) { // 1차 인증 스텝은 제외
            AuthenticationStepConfig step = configuredSteps.get(i);
            try {
                AuthType factorType = AuthType.valueOf(step.getType().toUpperCase());
                factorOptionsMap.put(factorType, (AuthenticationProcessingOptions) step.getOptions().get("_options"));
            } catch (IllegalArgumentException e) {
                throw new DslConfigurationException("Invalid AuthType string in stepConfig: " + step.getType());
            }
        }


        flowConfigBuilder
                .typeName(AuthType.MFA.name().toLowerCase())
                .order(this.order)
                // primaryAuthenticationOptions는 첫 번째 스텝의 옵션으로 대체 가능하거나, 그대로 유지하여 1차 인증 옵션 명시적 저장
                .primaryAuthenticationOptions((AuthenticationProcessingOptions) configuredSteps.get(0).getOptions().get("_options"))
                .stepConfigs(Collections.unmodifiableList(new ArrayList<>(this.configuredSteps))) // 전체 스텝 리스트 전달
                .mfaPolicyProvider(this.policyProvider)
                .mfaContinuationHandler(this.continuationHandler)
                .mfaFailureHandler(this.failureHandler)
                .finalSuccessHandler(this.finalSuccessHandler)
                .registeredFactorOptions(factorOptionsMap) // 2차 인증 요소들의 옵션
                .defaultRetryPolicy(this.defaultRetryPolicy)
                .defaultAdaptiveConfig(this.defaultAdaptiveConfig)
                .defaultDeviceTrustEnabled(this.defaultDeviceTrustEnabled);

        return flowConfigBuilder.build();
    }
}


