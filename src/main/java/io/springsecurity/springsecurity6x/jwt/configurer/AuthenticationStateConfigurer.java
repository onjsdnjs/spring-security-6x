package io.springsecurity.springsecurity6x.jwt.configurer;

import io.springsecurity.springsecurity6x.jwt.configurer.state.AuthenticationStateStrategy;
import io.springsecurity.springsecurity6x.jwt.configurer.state.JwtStateStrategy;
import io.springsecurity.springsecurity6x.jwt.configurer.state.SessionStateStrategy;

import java.util.function.Consumer;

public class AuthenticationStateConfigurer {

    private AuthenticationStateStrategy stateStrategy = new SessionStateStrategy(); // default

    public AuthenticationStateConfigurer useJwt(Consumer<JwtStateStrategy> config) {
        var jwt = new JwtStateStrategy();
        config.accept(jwt);
        this.stateStrategy = jwt;
        return this;
    }

    public AuthenticationStateConfigurer useSession() {
        this.stateStrategy = new SessionStateStrategy();
        return this;
    }

    public AuthenticationStateStrategy buildStrategy() {
        return stateStrategy;
    }
}


