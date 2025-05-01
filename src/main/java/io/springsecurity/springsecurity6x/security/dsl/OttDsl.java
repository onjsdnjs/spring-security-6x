package io.springsecurity.springsecurity6x.security.dsl;

public interface OttDsl {

    OttDsl matchers(String... patterns);

    OttDsl loginProcessingUrl(String url);

    IdentityStateDsl useSession();

    IdentityStateDsl useJwt();
}
