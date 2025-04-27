package io.springsecurity.springsecurity6x.security.dsl;

import io.springsecurity.springsecurity6x.security.dsl.authentication.*;
import io.springsecurity.springsecurity6x.security.dsl.state.AuthenticationStateDsl;
import io.springsecurity.springsecurity6x.security.dsl.state.AuthenticationStateStrategy;
import io.springsecurity.springsecurity6x.security.handler.AuthenticationHandlers;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class AuthIntegrationPlatformConfigurer extends AbstractHttpConfigurer<AuthIntegrationPlatformConfigurer, HttpSecurity> {

    private final ApplicationContext applicationContext;
    private RestAuthenticationDsl restDsl;
    private final List<AbstractAuthenticationDsl> authDslList = new ArrayList<>();
    private AuthenticationStateStrategy stateStrategy;

    private AuthIntegrationPlatformConfigurer(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    public static AuthIntegrationPlatformConfigurer custom(ApplicationContext applicationContext) {
        return new AuthIntegrationPlatformConfigurer(applicationContext);
    }

    public AuthIntegrationPlatformConfigurer rest(Consumer<RestAuthenticationDsl> consumer) {
        RestAuthenticationDsl dsl = new RestAuthenticationDsl();
        consumer.accept(dsl);
        authDslList.add(dsl);
        this.restDsl = dsl;
        return this;
    }

    public AuthIntegrationPlatformConfigurer form(Consumer<FormAuthenticationDsl> consumer) {
        FormAuthenticationDsl dsl = new FormAuthenticationDsl();
        consumer.accept(dsl);
        authDslList.add(dsl);
        return this;
    }

    public AuthIntegrationPlatformConfigurer ott(Consumer<OttAuthenticationDsl> consumer) {
        OttAuthenticationDsl dsl = new OttAuthenticationDsl();
        consumer.accept(dsl);
        authDslList.add(dsl);
        return this;
    }

    public AuthIntegrationPlatformConfigurer passkey(Consumer<PasskeyAuthenticationDsl> consumer) {
        PasskeyAuthenticationDsl dsl = new PasskeyAuthenticationDsl();
        consumer.accept(dsl);
        authDslList.add(dsl);
        return this;
    }

    public AuthIntegrationPlatformConfigurer state(Consumer<AuthenticationStateDsl> consumer) {

        AuthenticationStateDsl dsl = new AuthenticationStateDsl(applicationContext);
        consumer.accept(dsl);
        this.stateStrategy = dsl.build();
        return this;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {

        if (stateStrategy == null) throw new IllegalStateException("state() DSL 호출 필수");

        http.setSharedObject(AuthenticationStateStrategy.class, stateStrategy);
        http.setSharedObject(AuthenticationHandlers.class, stateStrategy.authHandlers());

        if (restDsl != null) {
            http.with(new RestAuthenticationConfigurer(), Customizer.withDefaults());
        }

        for (AbstractAuthenticationDsl dsl : authDslList) {
            dsl.init(http);
            dsl.configure(http);
        }
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
//        for (AbstractAuthenticationDsl dsl : authDslList) {
//            dsl.configure(http);
//        }
        stateStrategy.init(http);
        stateStrategy.configure(http);
    }
}




