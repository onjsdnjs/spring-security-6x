package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

public interface PasskeyDslConfigurer extends CommonSecurityDsl<PasskeyDslConfigurerImpl> {

    PasskeyDslConfigurer matchers(String... patterns);

    PasskeyDslConfigurer rpName(String name);

    PasskeyDslConfigurer rpId(String id);

    PasskeyDslConfigurer allowedOrigins(String... origins);
}

