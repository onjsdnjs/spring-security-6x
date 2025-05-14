package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.dsl.common.OptionsBuilderDsl;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;

public interface PasskeyDslConfigurer extends OptionsBuilderDsl<PasskeyOptions, PasskeyDslConfigurer> {

    PasskeyDslConfigurer rpName(String name);

    PasskeyDslConfigurer rpId(String id);

    PasskeyDslConfigurer allowedOrigins(String... origins);

    PasskeyDslConfigurer targetUrl(String url);
}

