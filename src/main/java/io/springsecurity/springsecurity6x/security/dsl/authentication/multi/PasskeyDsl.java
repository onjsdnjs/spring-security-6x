package io.springsecurity.springsecurity6x.security.dsl.authentication.multi;

public interface PasskeyDsl {

    PasskeyDsl matchers(String... patterns);

    PasskeyDsl rpName(String name);

    PasskeyDsl rpId(String id);

    PasskeyDsl allowedOrigins(String... origins);

    IdentityStateDsl useSession();

    IdentityStateDsl useJwt();
}
