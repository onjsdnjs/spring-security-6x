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
    private final Map<String, AuthenticationFlowConfig> flowMap = new HashMap<>();
    private final Map<String, Filter> factorFilters = new HashMap<>();

    public FeatureRegistry() {
        ServiceLoader.load(AuthenticationFeature.class)
                .forEach(f -> authFeatures.put(f.getId(), f));
        ServiceLoader.load(StateFeature.class)
                .forEach(f -> stateFeatures.put(f.getId(), f));
    }

    public List<AuthenticationFeature> getAllFeaturesFor(List<AuthenticationFlowConfig> flows) {
        List<AuthenticationFeature> result = new ArrayList<>();

        for (AuthenticationFlowConfig flow : flows) {
            String flowType = flow.typeName();

            // 1) MFA 컨테이너 Feature (typeName == "mfa") 가 존재하면 무조건 추가
            if ("mfa".equals(flowType)) {
                AuthenticationFeature mfaFeature = authFeatures.get("mfa");
                if (mfaFeature != null && !result.contains(mfaFeature)) {
                    result.add(mfaFeature);
                }
                // 2) 그 다음, MFA 플로우의 stepConfigs 에 정의된 각 스텝 타입별 Feature 추가
                for (AuthenticationStepConfig step : flow.stepConfigs()) {
                    String stepType = step.type();
                    AuthenticationFeature stepFeature = authFeatures.get(stepType);
                    if (stepFeature != null && !result.contains(stepFeature)) {
                        result.add(stepFeature);
                    }
                }
            }
            // 3) 만약 단일 스텝 플로우(form/rest 등)라면,
            //    flowType 자체가 그대로 Feature ID 와 매핑되므로
            //    단일 스텝 기능도 추가할 수 있습니다.
            else {
                AuthenticationFeature singleFeature = authFeatures.get(flowType);
                if (singleFeature != null && !result.contains(singleFeature)) {
                    result.add(singleFeature);
                }
            }
        }

        // 4) getOrder() 기준으로 정렬
        result.sort(Comparator.comparingInt(AuthenticationFeature::getOrder));
        return result;
    }

    /** 인증 플로우에 사용된 인증 기능 매핑 */
    public List<AuthenticationFeature> getAuthFeaturesFor(List<AuthenticationFlowConfig> flows) {
        Set<String> ids = flows.stream()
                .map(AuthenticationFlowConfig::typeName)
                .collect(Collectors.toSet());
        return ids.stream()
                .map(authFeatures::get)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    /** 플로우에 사용된 상태 기능 가지고 오기 */
    public List<StateFeature> getStateFeaturesFor(List<AuthenticationFlowConfig> flows) {
        Set<String> ids = flows.stream()
                .map(f -> f.stateConfig().state())
                .collect(Collectors.toSet());
        return ids.stream()
                .map(stateFeatures::get)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    /** 단일 플로우용 인증 기능 가져오기 */
    public AuthenticationFeature getAuthFeature(String flowId) {
        return authFeatures.get(flowId);
    }

    /** 단일 플로우용 상태 기능 가져오기 */
    public StateFeature getStateFeature(String stateId) {
        return stateFeatures.get(stateId);
    }

    public void registerFactorFilter(String factorType, Filter filter) {
        factorFilters.put(factorType, filter);
    }
    public Filter getFactorFilter(String factorType) {
        return factorFilters.get(factorType);
    }

    /**
     * 저장된 FlowConfig 반환
     */
    public AuthenticationFlowConfig getFlow(String flowId) {
        AuthenticationFlowConfig config = flowMap.get(flowId);
        if (config == null) {
            throw new IllegalArgumentException("Unknown flowId: " + flowId);
        }
        return config;
    }
}
