package io.springsecurity.springsecurity6x.security.dsl.authentication.multi;

public interface FormDsl {

    FormDsl matchers(String... patterns);

    FormDsl loginPage(String url);

    IdentityStateDsl useSession();

    IdentityStateDsl useJwt();
}
