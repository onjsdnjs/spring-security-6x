package io.springsecurity.springsecurity6x.security.init;

public interface IdentityStateDsl{
    IdentityDslRegistry useJwt();
    IdentityDslRegistry useSession();
}