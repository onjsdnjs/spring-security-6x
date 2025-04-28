package io.springsecurity.springsecurity6x.security.dsl;

import io.springsecurity.springsecurity6x.security.dsl.authentication.*;
import io.springsecurity.springsecurity6x.security.dsl.oauth2client.OAuth2ClientDsl;
import io.springsecurity.springsecurity6x.security.dsl.state.AuthenticationStateConfigurer;
import io.springsecurity.springsecurity6x.security.dsl.state.AuthenticationStateDsl;
import io.springsecurity.springsecurity6x.security.handler.AuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

public class AuthIntegrationPlatformConfigurer extends AbstractHttpConfigurer<AuthIntegrationPlatformConfigurer, HttpSecurity> {

    private RestAuthenticationDsl restDsl;
    private AuthenticationStateConfigurer stateConfigurer;
    private final AuthenticationStateDsl stateDsl;
    private final List<AbstractAuthenticationDsl> authDslList;
    private final AuthContextProperties properties;
    private OAuth2ClientDsl oauth2ClientDsl;

    public AuthIntegrationPlatformConfigurer(AuthenticationStateDsl stateDsl, AuthContextProperties properties) {
        this.stateDsl = stateDsl;
        this.properties = properties;
        this.authDslList = new ArrayList<>();
    }

    /*public static AuthIntegrationPlatformConfigurer build(AuthContextProperties props, SecretKey key) {
        AuthenticationStateDsl stateDsl = new AuthenticationStateDsl(props, key);
        return new AuthIntegrationPlatformConfigurer(stateDsl);
    }*/

    public AuthIntegrationPlatformConfigurer rest(Customizer<RestAuthenticationDsl> customizer) {
        RestAuthenticationDsl dsl = new RestAuthenticationDsl();
        customizer.customize(dsl);
        authDslList.add(dsl);
        this.restDsl = dsl;
        return this;
    }

    public AuthIntegrationPlatformConfigurer form(Customizer<FormAuthenticationDsl> customizer) {
        FormAuthenticationDsl dsl = new FormAuthenticationDsl();
        customizer.customize(dsl);
        authDslList.add(dsl);
        return this;
    }

    public AuthIntegrationPlatformConfigurer ott(Customizer<OttAuthenticationDsl> customizer) {
        OttAuthenticationDsl dsl = new OttAuthenticationDsl();
        customizer.customize(dsl);
        authDslList.add(dsl);
        return this;
    }

    public AuthIntegrationPlatformConfigurer passkey(Customizer<PasskeyAuthenticationDsl> customizer) {
        PasskeyAuthenticationDsl dsl = new PasskeyAuthenticationDsl();
        customizer.customize(dsl);
        authDslList.add(dsl);
        return this;
    }

    public AuthIntegrationPlatformConfigurer state(Function<AuthenticationStateDsl, AuthenticationStateConfigurer> fn) {
        this.stateConfigurer = fn.apply(stateDsl);
        return this;
    }

    public AuthIntegrationPlatformConfigurer oauth2Client(Customizer<OAuth2ClientDsl> customizer) {
        OAuth2ClientDsl dsl = new OAuth2ClientDsl(properties);
        customizer.customize(dsl);
        this.oauth2ClientDsl = dsl.build();
        return this;
    }

    public OAuth2ClientDsl oauth2ClientDsl() {
        if (oauth2ClientDsl == null) {
            throw new IllegalStateException("oauth2Client() DSL 호출 필수입니다.");
        }
        return oauth2ClientDsl;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {

        if (stateConfigurer == null) throw new IllegalStateException("state() DSL 호출 필수");

        stateConfigurer.init(http);
        stateConfigurer.configure(http);

        http.setSharedObject(AuthenticationStateConfigurer.class, stateConfigurer);
        http.setSharedObject(AuthenticationHandlers.class, stateConfigurer.authHandlers());

        if (restDsl != null) {
            http.with(new RestAuthenticationConfigurer(), Customizer.withDefaults());
        }

        for (AbstractAuthenticationDsl dsl : authDslList) {
            dsl.init(http);
            dsl.configure(http);
        }
    }
}
