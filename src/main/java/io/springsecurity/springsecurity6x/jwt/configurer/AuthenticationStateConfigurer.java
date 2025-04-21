package io.springsecurity.springsecurity6x.jwt.configurer;

import io.springsecurity.springsecurity6x.jwt.strategy.JwtStateStrategy;
import io.springsecurity.springsecurity6x.jwt.strategy.SessionStateStrategy;
import io.springsecurity.springsecurity6x.jwt.strategy.AuthenticationStateStrategy;

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


