package io.springsecurity.springsecurity6x.security.dsl;

public interface FormDsl {

    FormDsl matchers(String... patterns);

    FormDsl loginPage(String url);

    IdentityStateDsl useSession();

    IdentityStateDsl useJwt();
}
