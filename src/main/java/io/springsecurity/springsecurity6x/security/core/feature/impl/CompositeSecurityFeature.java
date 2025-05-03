package io.springsecurity.springsecurity6x.security.core.feature.impl;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.feature.SecurityFeature;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;
import java.util.function.Consumer;

public class CompositeSecurityFeature implements SecurityFeature {
    private final String id;
    private final List<AuthenticationFeature> steps;
    private final StateFeature state;
    private final Consumer<HttpSecurity> globalCustomizer;

    public CompositeSecurityFeature(String id, List<AuthenticationFeature> steps, StateFeature state, Consumer<HttpSecurity> globalCustomizer) {
        this.id = id;
        this.steps = steps;
        this.state = state;
        this.globalCustomizer = globalCustomizer;
    }

    @Override
    public void configure(PlatformContext ctx) throws Exception {
        HttpSecurity http = ctx.createBuilder(id);
        if (globalCustomizer != null) globalCustomizer.accept(http);
        state.apply(http, ctx);
        for (AuthenticationFeature step : steps) {
            step.apply(http, ctx);
        }
        SecurityFilterChain chain = http.build();
        ctx.registerChain(id, chain);
    }
}
