package io.springsecurity.springsecurity6x.security.core.dsl.factory;

import io.springsecurity.springsecurity6x.security.core.dsl.configurer.AuthenticationFactorConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.*;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.context.ApplicationContext;

public class AuthMethodConfigurerFactory {

    private final ApplicationContext applicationContext;

    public AuthMethodConfigurerFactory(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    public <O extends AuthenticationProcessingOptions, C extends AuthenticationFactorConfigurer<O, C>> C createConfigurer(AuthType authType) {
        return switch (authType) {
            case FORM -> (C) new FormDslConfigurerImpl();
            case REST -> (C) new RestDslConfigurerImpl();
            case OTT -> (C) new OttDslConfigurerImpl();
            case PASSKEY -> (C) new PasskeyDslConfigurerImpl();
            case RECOVERY_CODE -> (C) new RecoveryCodeDslConfigurerImpl();
            default -> throw new IllegalArgumentException("Unsupported authType for Configurer: " + authType);
        };
    }
}