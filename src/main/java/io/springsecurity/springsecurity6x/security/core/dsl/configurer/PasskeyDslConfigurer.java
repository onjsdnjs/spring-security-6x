package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;

import java.util.List;
import java.util.Set;

public interface PasskeyDslConfigurer extends AuthenticationFactorConfigurer<PasskeyOptions, PasskeyDslConfigurer> {

    PasskeyDslConfigurer assertionOptionsEndpoint(String url);
    PasskeyDslConfigurer rpName(String rpName);
    PasskeyDslConfigurer rpId(String rpId);
    PasskeyDslConfigurer allowedOrigins(List<String> origins); // 편의상 List도 허용
    PasskeyDslConfigurer allowedOrigins(String... origins); // varargs
    PasskeyDslConfigurer allowedOrigins(Set<String> origins); // Set도 허용
}

