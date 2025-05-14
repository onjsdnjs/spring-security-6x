package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.dsl.common.OptionsBuilderDsl;
import io.springsecurity.springsecurity6x.security.core.mfa.options.RestFactorOptions;

public interface RestStepDslConfigurer extends OptionsBuilderDsl<RestFactorOptions, RestStepDslConfigurer> {
    RestStepDslConfigurer order(int order);
}
