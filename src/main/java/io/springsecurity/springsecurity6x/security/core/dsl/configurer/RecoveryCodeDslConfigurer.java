package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.RestAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RecoveryCodeOptions;

public interface RecoveryCodeDslConfigurer extends AuthenticationFactorConfigurer<RecoveryCodeOptions, RestAsepAttributes, RecoveryCodeDslConfigurer>  {
    // RecoveryCodeFactorDslConfigurer recoveryCodeStore(RecoveryCodeStore recoveryCodeStore);
    // RecoveryCodeFactorDslConfigurer recoveryCodeStoreBeanName(String beanName);
    RecoveryCodeDslConfigurer codeLength(int length);
    RecoveryCodeDslConfigurer numberOfCodesToGenerate(int number);
}