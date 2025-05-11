package io.springsecurity.springsecurity6x.security.core.dsl.mfa.configurer;


import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.mfa.AdaptiveConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.mfa.RecoveryConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.mfa.RetryPolicy;

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
    public MfaDslConfigurer factor(Consumer<FactorDslConfigurer> c) {
        AuthenticationStepConfig step = new AuthenticationStepConfig();
        FactorDslConfigurerImpl impl = new FactorDslConfigurerImpl(step);
        c.accept(impl);
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
        // 기존 customizer 대신, MFA 설정은 FlowConfig 필드에 직접 담습니다.
        return flowBuilder
                .stepConfigs(stepConfigs)
                .stateConfig(null)
                .order(order)
                .retryPolicy(retryPolicy)          // 여기에 retryPolicy 담기
                .adaptiveConfig(adaptiveConfig)    // 여기에 adaptiveConfig 담기
                .deviceTrust(deviceTrust)          // 여기 deviceTrust 플래그 담기
                .recoveryConfig(recoveryConfig)    // 여기 recoveryConfig 담기
                .customizer(http -> {})            // 필요 시 전용 HttpSecurity 커스터마이즈
                .build();
    }
}


