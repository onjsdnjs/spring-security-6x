package io.springsecurity.springsecurity6x.security.dsl;

import io.springsecurity.springsecurity6x.security.config.IdentityConfig;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface IdentityDsl {

    FormDsl form(Customizer<FormDsl> customizer);
    RestDsl rest(Customizer<RestDsl> customizer);
    PasskeyDsl passkey(Customizer<PasskeyDsl> customizer);
    OttDsl ott(Customizer<OttDsl> customizer);
    IdentityStateDsl customize(Customizer<HttpSecurity> httpCustomizer) throws Exception;
    IdentityConfig getConfig();
}