package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.PasskeyAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;

import java.util.List;
import java.util.Set;

public interface PasskeyDslConfigurer extends AuthenticationFactorConfigurer<PasskeyOptions, PasskeyAsepAttributes, PasskeyDslConfigurer> {

    PasskeyDslConfigurer assertionOptionsEndpoint(String url);
    PasskeyDslConfigurer rpName(String rpName);
    PasskeyDslConfigurer rpId(String rpId);
    PasskeyDslConfigurer allowedOrigins(List<String> origins);
    PasskeyDslConfigurer allowedOrigins(String... origins);
    PasskeyDslConfigurer allowedOrigins(Set<String> origins);
}

