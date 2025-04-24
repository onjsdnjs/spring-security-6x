package io.springsecurity.springsecurity6x.security.configurer;

import io.springsecurity.springsecurity6x.security.configurer.authentication.ApiAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.configurer.authentication.AuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.configurer.authentication.OttLoginConfigurer;
import io.springsecurity.springsecurity6x.security.configurer.authentication.WebAuthnLoginConfigurer;
import org.springframework.security.config.Customizer;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class AuthenticationTypesConfigurer {

    private final List<AuthenticationConfigurer> entries = new ArrayList<>();

    public AuthenticationTypesConfigurer form(Customizer<ApiAuthenticationConfigurer> config) {
        ApiAuthenticationConfigurer form = new ApiAuthenticationConfigurer();
        config.customize(form);
        entries.add(form);
        return this;
    }

    public AuthenticationTypesConfigurer ott(Customizer<OttLoginConfigurer> config) {
        OttLoginConfigurer ott = new OttLoginConfigurer();
        config.customize(ott);
        entries.add(ott);
        return this;
    }

    public AuthenticationTypesConfigurer passkey(Customizer<WebAuthnLoginConfigurer> config) {
        WebAuthnLoginConfigurer passkey = new WebAuthnLoginConfigurer();
        config.customize(passkey);
        entries.add(passkey);
        return this;
    }

    public List<AuthenticationConfigurer> getEntries() {
        return entries;
    }
}


