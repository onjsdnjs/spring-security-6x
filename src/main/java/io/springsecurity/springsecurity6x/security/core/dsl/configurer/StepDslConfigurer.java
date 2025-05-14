package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;

public interface StepDslConfigurer {
    AuthenticationStepConfig toConfig();
    int getOrder();
    StepDslConfigurer order(int order);

}
