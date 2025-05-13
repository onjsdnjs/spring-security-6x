package io.springsecurity.springsecurity6x.security.core.mfa.configurer;


import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.*;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.FormDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.OttDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.PasskeyDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.RestDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.mfa.AdaptiveConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RecoveryConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import org.springframework.security.config.Customizer;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * MfaDslConfigurer 구현체
 */
public class MfaDslConfigurerImpl implements MfaDslConfigurer {

    private final AuthenticationFlowConfig.Builder flowBuilder;
    private final List<AuthenticationStepConfig> stepConfigs = new ArrayList<>();
    private int order;
    private String loginProcessingUrl = "/api/auth/mfa";
    private RetryPolicy retryPolicy;
    private AdaptiveConfig adaptiveConfig;
    private boolean deviceTrust;
    private RecoveryConfig recoveryConfig;

    public MfaDslConfigurerImpl(AuthenticationFlowConfig.Builder flowBuilder) {
        this.flowBuilder = flowBuilder;
    }

    private <C extends StepDslConfigurer> void addStep(Function<AuthenticationStepConfig, C> factory, Customizer<? super C> customizer) {
        AuthenticationStepConfig step = new AuthenticationStepConfig();
        C impl = factory.apply(step);
        customizer.customize(impl);
        stepConfigs.add(impl.toConfig());
    }

    @Override
    public MfaDslConfigurer form(Customizer<FormDslConfigurer> customizer) {
        addStep(FormDslConfigurerImpl::new, customizer);
        return this;
    }

    @Override
    public MfaDslConfigurer rest(Customizer<RestDslConfigurer> customizer) {
        addStep(RestDslConfigurerImpl::new, customizer);
        return this;
    }

    @Override
    public MfaDslConfigurer ott(Customizer<OttDslConfigurer> customizer) {
        addStep(OttDslConfigurerImpl::new, customizer);
        return this;
    }

    @Override
    public MfaDslConfigurer passkey(Customizer<PasskeyDslConfigurer> customizer) {
        addStep(PasskeyDslConfigurerImpl::new, customizer);
        return this;
    }

    @Override
    public MfaDslConfigurer order(int order) {
        this.order = order;
        return this;
    }

    @Override
    public MfaDslConfigurer loginProcessUrl(String url) {
        this.loginProcessingUrl = url;
        return this;
    }

    @Override
    public MfaDslConfigurer retryPolicy(Customizer<RetryPolicyDslConfigurer> c) {
        RetryPolicyDslConfigurerImpl rpc = new RetryPolicyDslConfigurerImpl();
        c.customize(rpc);
        this.retryPolicy = rpc.build();
        return this;
    }

    @Override
    public MfaDslConfigurer adaptive(Customizer<AdaptiveDslConfigurer> c) {
        AdaptiveDslConfigurerImpl adc = new AdaptiveDslConfigurerImpl();
        c.customize(adc);
        this.adaptiveConfig = adc.build();
        return this;
    }

    @Override
    public MfaDslConfigurer deviceTrust(boolean enable) {
        this.deviceTrust = enable;
        return this;
    }

    @Override
    public MfaDslConfigurer recoveryFlow(Customizer<RecoveryDslConfigurer> c) {
        RecoveryDslConfigurerImpl rc = new RecoveryDslConfigurerImpl();
        c.customize(rc);
        this.recoveryConfig = rc.build();
        return this;
    }

    @Override
    public AuthenticationFlowConfig build() {

        for (AuthenticationStepConfig step : stepConfigs) {
            step.options().put("_mfa_loginUrl", loginProcessingUrl);
        }


        return flowBuilder
                .stepConfigs(stepConfigs)
                .stateConfig(null)
                .order(order)
                .retryPolicy(retryPolicy)
                .adaptiveConfig(adaptiveConfig)
                .deviceTrust(deviceTrust)
                .recoveryConfig(recoveryConfig)
//                .customizer(http -> http.securityMatcher(loginProcessingUrl))
                .build();
    }
}


