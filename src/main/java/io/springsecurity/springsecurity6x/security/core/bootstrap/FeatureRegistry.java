package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.mfa.FactorAuthenticator;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * DSL 플로우에 매핑된 Feature 들을 중앙에서 관리합니다.
 */
public class FeatureRegistry {
    private final Map<String, AuthenticationFeature> authFeatures = new ConcurrentHashMap<>();
    private final Map<String, StateFeature> stateFeatures = new ConcurrentHashMap<>();
    private final Map<String, AuthenticationFlowConfig> flowMap = new ConcurrentHashMap<>();
    private final Map<String, FactorAuthenticator> authenticators = new ConcurrentHashMap<>();

    public FeatureRegistry() {
        ServiceLoader.load(AuthenticationFeature.class)
                .forEach(f -> authFeatures.put(f.getId(), f));
        ServiceLoader.load(StateFeature.class)
                .forEach(f -> stateFeatures.put(f.getId(), f));
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

    /**
     * AuthenticationFlowConfig 등록
     */
    public void registerFlow(AuthenticationFlowConfig config) {
        flowMap.put(config.typeName(), config);
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

    public FactorAuthenticator getFactorAuthenticator(String factorType) {
        return authenticators.get(factorType);
    }
}
