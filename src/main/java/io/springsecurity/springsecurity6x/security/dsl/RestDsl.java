package io.springsecurity.springsecurity6x.security.dsl;

public interface RestDsl {

    RestDsl matchers(String... patterns);

    RestDsl loginProcessingUrl(String url);

    IdentityStateDsl useSession();

    IdentityStateDsl useJwt();
}

