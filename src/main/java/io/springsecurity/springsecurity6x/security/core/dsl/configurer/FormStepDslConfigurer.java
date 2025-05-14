package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

public interface FormStepDslConfigurer extends FormDslConfigurer, StepDslConfigurer {
    FormStepDslConfigurer order(int order);
}

