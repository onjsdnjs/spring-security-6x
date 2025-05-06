package io.springsecurity.springsecurity6x.security.core.feature;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 인증 기능을 관리하고, PlatformConfig에 정의된 각 인증 플로우를
 * 적절한 AuthenticationFeature에 위임하여 적용합니다.
 */
public class AuthenticationFeatureRegistry {

    private final Map<String, AuthenticationFeature> featuresMap;

    public AuthenticationFeatureRegistry(List<AuthenticationFeature> features) {
        this.featuresMap = features.stream()
                .collect(Collectors.toMap(AuthenticationFeature::getId, f -> f));
    }

    /**
     * PlatformConfig에 정의된 모든 인증 플로우에 대해:
     *  1) Flow-level 커스터마이저 적용
     *  2) 등록된 AuthenticationFeature를 찾아 apply() 호출
     */
    public void configure(HttpSecurity http, PlatformConfig config) throws Exception {

        if (config.getGlobal() != null) {
            config.getGlobal().customize(http);
        }
        // 각 Flow 처리
        for (AuthenticationFlowConfig flow : config.getFlows()) {
            flow.getCustomizer().accept(http);
            AuthenticationFeature feature = featuresMap.get(flow.getTypeName());
            if (feature == null) {
                throw new IllegalStateException("No AuthenticationFeature for type: " + flow.getTypeName());
            }
            feature.apply(http, flow.getStepConfigs(), flow.getStateConfig());
        }
    }
}
