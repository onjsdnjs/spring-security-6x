package io.springsecurity.springsecurity6x.security.core.dsl.factor.recovery;

import io.springsecurity.springsecurity6x.security.core.dsl.configurer.FactorDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.options.recovery.RecoveryCodeFactorOptions;

public interface RecoveryCodeFactorDslConfigurer extends FactorDslConfigurer<RecoveryCodeFactorOptions, RecoveryCodeFactorDslConfigurer> {
    // RecoveryCodeFactorDslConfigurer recoveryCodeStore(RecoveryCodeStore recoveryCodeStore);
    // RecoveryCodeFactorDslConfigurer recoveryCodeStoreBeanName(String beanName);
    RecoveryCodeFactorDslConfigurer codeLength(int length);
    RecoveryCodeFactorDslConfigurer numberOfCodesToGenerate(int number);
}