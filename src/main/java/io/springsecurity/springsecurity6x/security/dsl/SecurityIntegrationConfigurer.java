package io.springsecurity.springsecurity6x.security.dsl;

import io.springsecurity.springsecurity6x.security.dsl.authentication.*;
import io.springsecurity.springsecurity6x.security.dsl.state.AuthenticationStateDsl;
import io.springsecurity.springsecurity6x.security.dsl.state.AuthenticationStateStrategy;
import io.springsecurity.springsecurity6x.security.dsl.state.JwtStateStrategy;
import io.springsecurity.springsecurity6x.security.dsl.state.SessionStateStrategy;
import io.springsecurity.springsecurity6x.security.handler.StrategyAwareLogoutSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.TokenLogoutHandler;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class SecurityIntegrationConfigurer extends AbstractHttpConfigurer<SecurityIntegrationConfigurer, HttpSecurity> {

    private RestAuthenticationDsl restDsl;
    private final List<AbstractAuthenticationDsl> authDslList = new ArrayList<>();
    private AuthenticationStateStrategy stateStrategy;

    private SecurityIntegrationConfigurer() {}

    public static SecurityIntegrationConfigurer custom() { return new SecurityIntegrationConfigurer(); }

    public SecurityIntegrationConfigurer rest(Consumer<RestAuthenticationDsl> consumer) {
        RestAuthenticationDsl dsl = new RestAuthenticationDsl();
        consumer.accept(dsl);
        this.restDsl = dsl;
        return this;
    }

    public SecurityIntegrationConfigurer form(Consumer<FormAuthenticationDsl> consumer) {
        FormAuthenticationDsl dsl = new FormAuthenticationDsl();
        consumer.accept(dsl);
        authDslList.add(dsl);
        return this;
    }

    public SecurityIntegrationConfigurer ott(Consumer<OttAuthenticationDsl> consumer) {
        OttAuthenticationDsl dsl = new OttAuthenticationDsl();
        consumer.accept(dsl);
        authDslList.add(dsl);
        return this;
    }

    public SecurityIntegrationConfigurer passkey(Consumer<PasskeyAuthenticationDsl> consumer) {
        PasskeyAuthenticationDsl dsl = new PasskeyAuthenticationDsl();
        consumer.accept(dsl);
        authDslList.add(dsl);
        return this;
    }

    public SecurityIntegrationConfigurer state(Consumer<AuthenticationStateDsl> consumer) {
        AuthenticationStateDsl dsl = new AuthenticationStateDsl();
        consumer.accept(dsl);
        this.stateStrategy = dsl.build();
        return this;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {

        if (stateStrategy == null) throw new IllegalStateException("state() DSL 호출 필수");

        http.setSharedObject(AuthenticationStateStrategy.class, stateStrategy);
        stateStrategy.init(http);

        if (restDsl != null) {
            http.with(new RestLoginConfigurer(), Customizer.withDefaults());
        }

        for (AbstractAuthenticationDsl dsl : authDslList) {
            dsl.init(http);
        }
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        for (AbstractAuthenticationDsl dsl : authDslList) {
            dsl.configure(http);
        }
        stateStrategy.configure(http);
    }
}




