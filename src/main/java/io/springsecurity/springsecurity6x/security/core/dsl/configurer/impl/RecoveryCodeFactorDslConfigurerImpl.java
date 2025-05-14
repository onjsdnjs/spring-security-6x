package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factor.recovery.RecoveryCodeFactorDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.options.RecoveryCodeFactorOptions;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class RecoveryCodeFactorDslConfigurerImpl
        extends AbstractOptionsBuilderConfigurer<RecoveryCodeFactorOptions, RecoveryCodeFactorOptions.Builder, RecoveryCodeFactorDslConfigurer>
        implements RecoveryCodeFactorDslConfigurer {

    public RecoveryCodeFactorDslConfigurerImpl() {
        super(RecoveryCodeFactorOptions.builder()); // RecoveryCodeFactorOptions에 Builder 추가 필요
    }

    @Override
    protected RecoveryCodeFactorDslConfigurer self() { return this; }

    @Override
    public RecoveryCodeFactorDslConfigurer processingUrl(String url) {
        this.optionsBuilder.processingUrl(url); return self();
    }
    @Override
    public RecoveryCodeFactorDslConfigurer successHandler(AuthenticationSuccessHandler handler) {
        this.optionsBuilder.successHandler(handler); return self();
    }
    @Override
    public RecoveryCodeFactorDslConfigurer failureHandler(AuthenticationFailureHandler handler) {
        this.optionsBuilder.failureHandler(handler); return self();
    }

    /*
    @Override
    public RecoveryCodeFactorDslConfigurer recoveryCodeStore(RecoveryCodeStore recoveryCodeStore) {
        this.optionsBuilder.recoveryCodeStore(recoveryCodeStore); // RecoveryCodeFactorOptions.Builder에 추가
        return this;
    }
    */

    @Override
    public RecoveryCodeFactorDslConfigurer codeLength(int length) {
        this.optionsBuilder.codeLength(length); // RecoveryCodeFactorOptions.Builder에 추가
        return self();
    }

    @Override
    public RecoveryCodeFactorDslConfigurer numberOfCodesToGenerate(int number) {
        this.optionsBuilder.numberOfCodesToGenerate(number); // RecoveryCodeFactorOptions.Builder에 추가
        return self();
    }
}
