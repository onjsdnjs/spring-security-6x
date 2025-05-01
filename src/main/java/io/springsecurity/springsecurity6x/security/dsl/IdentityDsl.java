package io.springsecurity.springsecurity6x.security.dsl;

import org.springframework.security.config.Customizer;

public interface IdentityDsl {
    FormDsl form(Customizer<FormDsl> customizer);
    RestDsl rest(Customizer<RestDsl> customizer);
    PasskeyDsl passkey(Customizer<PasskeyDsl> customizer);
    OttDsl ott(Customizer<OttDsl> customizer);

    IdentityStateDsl customize(Customizer<org.springframework.security.config.annotation.web.builders.HttpSecurity> customizer);
}