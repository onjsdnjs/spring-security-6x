package io.springsecurity.springsecurity6x.security.dsl;

public interface PasskeyDsl {

    PasskeyDsl matchers(String... patterns);

    PasskeyDsl rpName(String name);

    PasskeyDsl rpId(String id);

    PasskeyDsl allowedOrigins(String... origins);

    IdentityStateDsl useSession();

    IdentityStateDsl useJwt();
}
