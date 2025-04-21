package io.springsecurity.springsecurity6x.jwt.configurer;

import io.springsecurity.springsecurity6x.jwt.configurer.authentication.ApiAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.jwt.configurer.authentication.AuthenticationEntryConfigurer;
import io.springsecurity.springsecurity6x.jwt.configurer.authentication.OttAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.jwt.configurer.authentication.PasskeyAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.jwt.configurer.state.AuthenticationStateStrategy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

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

    public void configure(HttpSecurity http, AuthenticationStateStrategy strategy) throws Exception {
        for (AuthenticationEntryConfigurer entry : entries) {
            entry.setStateStrategy(strategy);
            entry.configure(http);
        }
    }

    public List<AuthenticationEntryConfigurer> getEntries() {
        return entries;
    }
}


