package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import jakarta.servlet.Filter;

import java.util.*;
import java.util.stream.Collectors;

/**
 * DSL 플로우에 매핑된 Feature 들을 중앙에서 관리합니다.
 */
public class FeatureRegistry {
    private final Map<String, AuthenticationFeature> authFeatures = new HashMap<>();
    private final Map<String, StateFeature> stateFeatures = new HashMap<>();
    private final Map<String, Filter> factorFilters = new HashMap<>();

    public FeatureRegistry() {
        ServiceLoader.load(AuthenticationFeature.class)
                .forEach(f -> authFeatures.put(f.getId(), f));
        ServiceLoader.load(StateFeature.class)
                .forEach(f -> stateFeatures.put(f.getId(), f));
    }

    public List<AuthenticationFeature> getAuthFeaturesFor(List<AuthenticationFlowConfig> flows) {
        List<AuthenticationFeature> result = new ArrayList<>();
        for (AuthenticationFlowConfig flow : flows) {
            if ("mfa".equals(flow.typeName())) {
                result.add(authFeatures.get("mfa"));
                flow.stepConfigs().forEach(step -> {
                    AuthenticationFeature feat = authFeatures.get(step.type());
                    if (feat != null) result.add(feat);
                });
            } else {
                AuthenticationFeature feat = authFeatures.get(flow.typeName());
                if (feat != null) result.add(feat);
            }
        }
        result.sort(Comparator.comparingInt(AuthenticationFeature::getOrder));
        return result;
    }

    public List<StateFeature> getStateFeaturesFor(List<AuthenticationFlowConfig> flows) {
        Set<String> ids = new HashSet<>();
        for (AuthenticationFlowConfig f : flows) ids.add(f.stateConfig().state());
        List<StateFeature> list = new ArrayList<>();
        ids.forEach(id -> {
            StateFeature sf = stateFeatures.get(id);
            if (sf != null) list.add(sf);
        });
        return list;
    }

    public void registerFactorFilter(String factorType, Filter filter) {
        factorFilters.put(factorType, filter);
    }

    public Filter getFactorFilter(String factorType) {
        return factorFilters.get(factorType);
    }
}
