package io.springsecurity.springsecurity6x.security.dsl.authentication.multi;

import io.springsecurity.springsecurity6x.security.init.IdentityStateDsl;

public interface OttDsl {

    OttDsl matchers(String... patterns);

    OttDsl loginProcessingUrl(String url);

    IdentityStateDsl useSession();

    IdentityStateDsl useJwt();
}
