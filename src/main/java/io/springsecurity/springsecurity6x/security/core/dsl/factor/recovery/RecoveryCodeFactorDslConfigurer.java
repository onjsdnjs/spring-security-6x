package io.springsecurity.springsecurity6x.security.core.dsl.factor.recovery;

import io.springsecurity.springsecurity6x.security.core.dsl.common.OptionsBuilderDsl;
import io.springsecurity.springsecurity6x.security.core.mfa.options.passkey.PasskeyFactorOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.options.recovery.RecoveryCodeFactorOptions;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public interface RecoveryCodeFactorDslConfigurer extends OptionsBuilderDsl<RecoveryCodeFactorOptions, RecoveryCodeFactorDslConfigurer> {
    // RecoveryCodeFactorDslConfigurer recoveryCodeStore(RecoveryCodeStore recoveryCodeStore);
    // RecoveryCodeFactorDslConfigurer recoveryCodeStoreBeanName(String beanName);
    RecoveryCodeFactorDslConfigurer codeLength(int length);
    RecoveryCodeFactorDslConfigurer numberOfCodesToGenerate(int number);
    RecoveryCodeFactorDslConfigurer processingUrl(String url);
    RecoveryCodeFactorDslConfigurer successHandler(AuthenticationSuccessHandler handler);
    RecoveryCodeFactorDslConfigurer failureHandler(AuthenticationFailureHandler handler);
}