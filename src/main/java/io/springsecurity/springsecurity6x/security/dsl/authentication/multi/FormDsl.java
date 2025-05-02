package io.springsecurity.springsecurity6x.security.dsl.authentication.multi;

import io.springsecurity.springsecurity6x.security.init.IdentityStateDsl;

public interface FormDsl {

    FormDsl matchers(String... patterns);

    FormDsl loginPage(String url);

    IdentityStateDsl useSession();

    IdentityStateDsl useJwt();
}
