package io.springsecurity.springsecurity6x.security.configurer;

import io.springsecurity.springsecurity6x.security.configurer.authentication.ApiAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.configurer.authentication.AuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.configurer.authentication.OttLoginConfigurer;
import io.springsecurity.springsecurity6x.security.configurer.authentication.WebAuthnLoginConfigurer;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class AuthenticationTypesConfigurer {

    private final List<AuthenticationConfigurer> entries = new ArrayList<>();

    public AuthenticationTypesConfigurer form(Consumer<ApiAuthenticationConfigurer> config) {
        ApiAuthenticationConfigurer form = new ApiAuthenticationConfigurer();
        config.accept(form);
        entries.add(form);
        return this;
    }

    public AuthenticationTypesConfigurer ott(Consumer<OttLoginConfigurer> config) {
        OttLoginConfigurer ott = new OttLoginConfigurer();
        config.accept(ott);
        entries.add(ott);
        return this;
    }

    public AuthenticationTypesConfigurer passkey(Consumer<WebAuthnLoginConfigurer> config) {
        WebAuthnLoginConfigurer passkey = new WebAuthnLoginConfigurer();
        config.accept(passkey);
        entries.add(passkey);
        return this;
    }

    public List<AuthenticationConfigurer> getEntries() {
        return entries;
    }
}


