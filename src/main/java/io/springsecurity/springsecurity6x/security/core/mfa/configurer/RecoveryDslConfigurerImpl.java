package io.springsecurity.springsecurity6x.security.core.mfa.configurer;

import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.RecoveryConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.options.RecoveryCodeFactorOptions;

public class RecoveryDslConfigurerImpl extends AbstractOptionsBuilderConfigurer<RecoveryCodeFactorOptions, RecoveryCodeFactorOptions.Builder, RecoveryDslConfigurer> implements RecoveryDslConfigurer {
    private String emailOtpEndpoint;
    private String smsOtpEndpoint;

    public RecoveryDslConfigurerImpl() {
        super(RecoveryCodeFactorOptions.builder());
    }

    @Override
    public RecoveryDslConfigurer emailOtpEndpoint(String endpoint) {
        this.emailOtpEndpoint = endpoint;
        return this;
    }

    @Override
    public RecoveryDslConfigurer smsOtpEndpoint(String endpoint) {
        this.smsOtpEndpoint = endpoint;
        return this;
    }

    @Override
    public RecoveryConfig build() {
        return new RecoveryConfig(emailOtpEndpoint, smsOtpEndpoint);
    }

    @Override
    protected RecoveryDslConfigurer self() {
        return this;
    }
}

