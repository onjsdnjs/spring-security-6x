package io.springsecurity.springsecurity6x.jwt.configurer;

import io.springsecurity.springsecurity6x.jwt.configurer.authentication.ApiAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.jwt.configurer.authentication.AuthenticationEntryConfigurer;
import io.springsecurity.springsecurity6x.jwt.configurer.authentication.OttAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.jwt.configurer.authentication.PasskeyAuthenticationConfigurer;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class AuthenticationTypeConfigurer {

    private final List<AuthenticationEntryConfigurer> entries = new ArrayList<>();

    public AuthenticationTypeConfigurer form(Consumer<ApiAuthenticationConfigurer> config) {
        ApiAuthenticationConfigurer form = new ApiAuthenticationConfigurer();
        config.accept(form);
        entries.add(form);
        return this;
    }

    public AuthenticationTypeConfigurer ott(Consumer<OttAuthenticationConfigurer> config) {
        OttAuthenticationConfigurer ott = new OttAuthenticationConfigurer();
        config.accept(ott);
        entries.add(ott);
        return this;
    }

    public AuthenticationTypeConfigurer passkey(Consumer<PasskeyAuthenticationConfigurer> config) {
        PasskeyAuthenticationConfigurer passkey = new PasskeyAuthenticationConfigurer();
        config.accept(passkey);
        entries.add(passkey);
        return this;
    }

    public List<AuthenticationEntryConfigurer> getEntries() {
        return entries;
    }
}


