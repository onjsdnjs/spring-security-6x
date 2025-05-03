package io.springsecurity.springsecurity6x.security.core.feature;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class AuthenticationFeatureRegistry {
    private final Map<String, AuthenticationFeature> features;

    public AuthenticationFeatureRegistry(List<AuthenticationFeature> list) {
        features = list.stream()
                .collect(Collectors.toMap(AuthenticationFeature::getId, f -> f));
    }

    public void configure(HttpSecurity http, PlatformContext ctx) throws Exception {
        for (AuthenticationConfig ac : ctx.getAuthConfigs()) {
            AuthenticationFeature feature = features.get(ac.type());
            feature.apply(http, ctx);
        }
    }
}
