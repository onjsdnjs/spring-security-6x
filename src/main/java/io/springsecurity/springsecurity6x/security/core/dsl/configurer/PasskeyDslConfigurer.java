package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.dsl.CommonSecurityDsl;

public interface PasskeyDslConfigurer extends CommonSecurityDsl<PasskeyDslConfigurer> {

    PasskeyDslConfigurer rpName(String name);

    PasskeyDslConfigurer rpId(String id);

    PasskeyDslConfigurer allowedOrigins(String... origins);

    PasskeyDslConfigurer targetUrl(String url);
}

