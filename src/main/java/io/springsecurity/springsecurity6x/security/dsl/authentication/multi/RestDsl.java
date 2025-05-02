package io.springsecurity.springsecurity6x.security.dsl.authentication.multi;

import io.springsecurity.springsecurity6x.security.init.IdentityStateDsl;

public interface RestDsl {

    RestDsl matchers(String... patterns);

    RestDsl loginProcessingUrl(String url);

    IdentityStateDsl useSession();

    IdentityStateDsl useJwt();
}

