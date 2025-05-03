package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class SecurityPlatformImpl implements SecurityPlatform {

    private final ApplicationContext context;
    private PlatformConfig platformConfig;
    private List<AuthenticationFeature> features;

    @Autowired
    public SecurityPlatformImpl(ApplicationContext context) {
        this.context = context;
    }

    @Override
    public void prepareGlobal(PlatformConfig config, List<AuthenticationFeature> features) {
        this.platformConfig = config;
        this.features = features;
    }

    @Override
    public void initialize() throws Exception {
        // Create HttpSecurity and SecurityFilterChain bean via builder
        HttpSecurity http = context.getBean(HttpSecurity.class);

        // 1) global 설정
        if (platformConfig.getGlobal() != null) {
            platformConfig.getGlobal().customize(http);
        }

        // 2) flows
        for (AuthenticationFlowConfig flow : platformConfig.getFlows()) {
            flow.getCustomizer().accept(http);
            Map<String, AuthenticationFeature> featureMap = features.stream()
                    .collect(Collectors.toMap(AuthenticationFeature::getId, f -> f));
            AuthenticationFeature feature = featureMap.get(flow.getType());
            feature.apply(http, flow.getSteps(), flow.getState());
        }

        // register SecurityFilterChain
        SecurityFilterChain chain = http.build();
        // register chain in context (requires manual registration in BeanFactory)
        // skipped for brevity
    }
}
