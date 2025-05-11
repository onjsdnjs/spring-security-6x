package io.springsecurity.springsecurity6x.security.core.mfa.configurer;


import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.OttDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.PasskeyDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RestDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.OttDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.PasskeyDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.RestDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.mfa.AdaptiveConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RecoveryConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * MfaDslConfigurer 구현체
 */
public class MfaDslConfigurerImpl implements MfaDslConfigurer {
    private final AuthenticationFlowConfig.Builder flowBuilder;
    private final List<AuthenticationStepConfig> stepConfigs = new ArrayList<>();
    private int order;
    private RetryPolicy retryPolicy;
    private AdaptiveConfig adaptiveConfig;
    private boolean deviceTrust;
    private RecoveryConfig recoveryConfig;

    public MfaDslConfigurerImpl(AuthenticationFlowConfig.Builder flowBuilder) {
        this.flowBuilder = flowBuilder;
    }

    @Override
    public MfaDslConfigurer rest(Consumer<RestDslConfigurer> customizer) {
        AuthenticationStepConfig step = new AuthenticationStepConfig();
        RestDslConfigurerImpl impl = new RestDslConfigurerImpl(step);
        customizer.accept(impl);
        stepConfigs.add(impl.toConfig());
        return this;
    }

    @Override
    public MfaDslConfigurer ott(Consumer<OttDslConfigurer> customizer) {
        AuthenticationStepConfig step = new AuthenticationStepConfig();
        OttDslConfigurerImpl impl = new OttDslConfigurerImpl(step);
        customizer.accept(impl);
        stepConfigs.add(impl.toConfig());
        return this;
    }

    @Override
    public MfaDslConfigurer passkey(Consumer<PasskeyDslConfigurer> customizer) {
        AuthenticationStepConfig step = new AuthenticationStepConfig();
        PasskeyDslConfigurerImpl impl = new PasskeyDslConfigurerImpl(step);
        customizer.accept(impl);
        stepConfigs.add(impl.toConfig());
        return this;
    }

    @Override
    public MfaDslConfigurer order(int order) {
        this.order = order;
        return this;
    }

    @Override
    public MfaDslConfigurer retryPolicy(Consumer<RetryPolicyDslConfigurer> c) {
        RetryPolicyDslConfigurerImpl rpc = new RetryPolicyDslConfigurerImpl();
        c.accept(rpc);
        this.retryPolicy = rpc.build();
        return this;
    }

    @Override
    public MfaDslConfigurer adaptive(Consumer<AdaptiveDslConfigurer> c) {
        AdaptiveDslConfigurerImpl adc = new AdaptiveDslConfigurerImpl();
        c.accept(adc);
        this.adaptiveConfig = adc.build();
        return this;
    }

    @Override
    public MfaDslConfigurer deviceTrust(boolean enable) {
        this.deviceTrust = enable;
        return this;
    }

    @Override
    public MfaDslConfigurer recoveryFlow(Consumer<RecoveryDslConfigurer> c) {
        RecoveryDslConfigurerImpl rc = new RecoveryDslConfigurerImpl();
        c.accept(rc);
        this.recoveryConfig = rc.build();
        return this;
    }

    @Override
    public AuthenticationFlowConfig build() {
        return flowBuilder
                .stepConfigs(stepConfigs)
                .stateConfig(null)
                .order(order)
                .retryPolicy(retryPolicy)
                .adaptiveConfig(adaptiveConfig)
                .deviceTrust(deviceTrust)
                .recoveryConfig(recoveryConfig)
                .customizer(http -> {})
                .build();
    }
}


