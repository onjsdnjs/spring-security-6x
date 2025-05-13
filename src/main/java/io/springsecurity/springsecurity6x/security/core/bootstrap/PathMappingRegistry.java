package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class PathMappingRegistry {
    private final Set<String> singleAuthPaths = new HashSet<>();
    private final Set<String> mfaEntryPaths = new HashSet<>();
    private final Map<String, String> mfaStepPaths = new LinkedHashMap<>(); // loginUrl -> stepType
    private final Map<String, String> mfaStepTargetUrls = new LinkedHashMap<>(); // stepType -> targetUrl

    /**
     * DSL 설정의 AuthenticationFlowConfig를 기반으로
     * 단일 인증 경로와 MFA 진입점 및 단계별 경로를 수집합니다.
     * 충돌 검증은 ConflictRiskAnalyzer 에서 수행합니다.
     */
    public PathMappingRegistry(PlatformConfig config) {
        for (AuthenticationFlowConfig flow : config.flows()) {
            String type = flow.typeName().toLowerCase();
            String entryUrl = flow.loginProcessingUrl();
            if ("mfa".equals(type)) {
                // MFA 진입점 수집
                mfaEntryPaths.add(entryUrl);
                // MFA 단계별 경로 및 targetUrl 수집
                for (AuthenticationStepConfig step : flow.stepConfigs()) {
                    String stepType = step.type();
                    String loginUrl = step.loginProcessingUrl();
                    mfaStepPaths.put(loginUrl, stepType);
                    // 옵션에서 targetUrl 추출
                    Object opts = step.options().get("_options");
                    String targetUrl = null;
                    if (opts instanceof FormOptions) {
                        targetUrl = ((FormOptions) opts).getTargetUrl();
                    } else if (opts instanceof OttOptions) {
                        targetUrl = ((OttOptions) opts).getTargetUrl();
                    } else if (opts instanceof PasskeyOptions) {
                        targetUrl = ((PasskeyOptions) opts).getTargetUrl();
                    }
                    mfaStepTargetUrls.put(stepType, targetUrl);
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
    public Map<String, String> mfaStepTargetUrls() {
        return mfaStepTargetUrls;
    }
}
