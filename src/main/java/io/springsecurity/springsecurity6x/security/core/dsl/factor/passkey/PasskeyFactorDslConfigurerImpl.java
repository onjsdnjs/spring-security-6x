package io.springsecurity.springsecurity6x.security.core.dsl.factor.passkey;

import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.options.passkey.PasskeyFactorOptions;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class PasskeyFactorDslConfigurerImpl
        extends AbstractOptionsBuilderConfigurer<PasskeyFactorOptions, PasskeyFactorOptions.Builder, PasskeyFactorDslConfigurer>
        implements PasskeyFactorDslConfigurer {

    public PasskeyFactorDslConfigurerImpl() {
        super(PasskeyFactorOptions.builder());
    }

    @Override
    protected PasskeyFactorDslConfigurer self() { return this; }

    @Override
    public PasskeyFactorDslConfigurer processingUrl(String url) {
        this.optionsBuilder.processingUrl(url); return self();
    }
    @Override
    public PasskeyFactorDslConfigurer successHandler(AuthenticationSuccessHandler handler) {
        this.optionsBuilder.successHandler(handler); return self();
    }
    @Override
    public PasskeyFactorDslConfigurer failureHandler(AuthenticationFailureHandler handler) {
        this.optionsBuilder.failureHandler(handler); return self();
    }
    @Override
    public PasskeyFactorDslConfigurer rpName(String rpName) {
        this.optionsBuilder.rpName(rpName); return self();
    }
    @Override
    public PasskeyFactorDslConfigurer rpId(String rpId) {
        this.optionsBuilder.rpId(rpId); return self();
    }
    @Override
    public PasskeyFactorDslConfigurer allowedOrigins(String... origins) {
        if (origins != null) {
            this.optionsBuilder.allowedOrigins(new HashSet<>(Arrays.asList(origins)));
        }
        return self();
    }
    @Override
    public PasskeyFactorDslConfigurer allowedOrigins(Set<String> origins) {
        this.optionsBuilder.allowedOrigins(origins); return self();
    }
}
