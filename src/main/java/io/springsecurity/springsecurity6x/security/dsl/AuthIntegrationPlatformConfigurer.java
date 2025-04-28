package io.springsecurity.springsecurity6x.security.dsl;

import io.springsecurity.springsecurity6x.security.dsl.authentication.*;
import io.springsecurity.springsecurity6x.security.dsl.state.AuthenticationStateConfigurer;
import io.springsecurity.springsecurity6x.security.dsl.state.AuthenticationStateDsl;
import io.springsecurity.springsecurity6x.security.handler.AuthenticationHandlers;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import java.util.ArrayList;
import java.util.List;

public class AuthIntegrationPlatformConfigurer extends AbstractHttpConfigurer<AuthIntegrationPlatformConfigurer, HttpSecurity> {

    private final ApplicationContext applicationContext;
    private RestAuthenticationDsl restDsl;
    private final List<AbstractAuthenticationDsl> authDslList = new ArrayList<>();
    private AuthenticationStateConfigurer stateConfigurer;

    private AuthIntegrationPlatformConfigurer(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    public static AuthIntegrationPlatformConfigurer custom(ApplicationContext applicationContext) {
        return new AuthIntegrationPlatformConfigurer(applicationContext);
    }

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

    public AuthIntegrationPlatformConfigurer state(Customizer<AuthenticationStateDsl> customizer) {

        AuthenticationStateDsl dsl = new AuthenticationStateDsl(applicationContext);
        customizer.customize(dsl);
        this.stateConfigurer = dsl.build();
        return this;
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
