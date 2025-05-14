package io.springsecurity.springsecurity6x.security.core.dsl.factor.passkey;

import io.springsecurity.springsecurity6x.security.core.dsl.common.OptionsBuilderDsl;
import io.springsecurity.springsecurity6x.security.core.mfa.options.passkey.PasskeyFactorOptions;
import org.springframework.security.web.authentication.AuthenticationFailureHandler; // 추가
import org.springframework.security.web.authentication.AuthenticationSuccessHandler; // 추가
import java.util.Set;

public interface PasskeyFactorDslConfigurer extends OptionsBuilderDsl<PasskeyFactorOptions, PasskeyFactorDslConfigurer> {
    PasskeyFactorDslConfigurer processingUrl(String url); // 공통 메소드로 추가
    PasskeyFactorDslConfigurer successHandler(AuthenticationSuccessHandler handler); // 공통 메소드로 추가
    PasskeyFactorDslConfigurer failureHandler(AuthenticationFailureHandler handler); // 공통 메소드로 추가
    PasskeyFactorDslConfigurer rpName(String rpName);
    PasskeyFactorDslConfigurer rpId(String rpId);
    PasskeyFactorDslConfigurer allowedOrigins(String... origins);
    PasskeyFactorDslConfigurer allowedOrigins(Set<String> origins);
}
