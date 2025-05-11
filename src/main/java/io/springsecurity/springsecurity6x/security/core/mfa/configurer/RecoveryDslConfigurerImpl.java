package io.springsecurity.springsecurity6x.security.core.mfa.configurer;

import io.springsecurity.springsecurity6x.security.core.mfa.RecoveryConfig;

public class RecoveryDslConfigurerImpl implements RecoveryDslConfigurer {
    private String emailOtpEndpoint;
    private String smsOtpEndpoint;

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
}

