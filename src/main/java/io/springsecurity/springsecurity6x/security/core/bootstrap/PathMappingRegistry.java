package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.exception.DslValidationException;

import java.util.*;

public class PathMappingRegistry {
    private final Set<String> singleAuthPaths = new HashSet<>();
    private final Set<String> mfaEntryPaths    = new HashSet<>();
    private final Map<String,String> mfaStepPaths = new LinkedHashMap<>(); // path -> stepId

    /**
     * DSL 설정의 AuthenticationFlowConfig를 기반으로
     * 단일 인증 경로와 MFA 진입점 및 단계별 경로를 수집합니다.
     * 충돌 검증은 ConflictRiskAnalyzer에서 수행합니다.
     */
    public PathMappingRegistry(PlatformConfig config) {
        for (AuthenticationFlowConfig flow : config.flows()) {
            String type = flow.typeName().toLowerCase();
            String entry = flow.loginProcessingUrl();
            if ("mfa".equals(type)) {
                // MFA 진입점 수집
                mfaEntryPaths.add(entry);
                // MFA 단계별 경로 수집
                for (AuthenticationStepConfig step : flow.stepConfigs()) {
                    mfaStepPaths.put(step.loginProcessingUrl(), step.type());
                }
            } else {
                // 단일 인증 경로 수집
                for (AuthenticationStepConfig step : flow.stepConfigs()) {
                    singleAuthPaths.add(step.loginProcessingUrl());
                }
            }
        }
    }

    public Set<String> singleAuthPaths() {
        return singleAuthPaths;
    }

    public Set<String> mfaEntryPaths() {
        return mfaEntryPaths;
    }

    public Map<String, String> mfaStepPaths() {
        return mfaStepPaths;
    }
}
