package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.exception.DslValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;


/**
 * MFA 흐름 중복 검증기
 * - 각 FlowContext를 순회하며 MFA 흐름을 검사합니다.
 * - 진입점과 단계 순서가 동일하고 옵션까지 동일한 경우 오류를 발생시킵니다.
 * - 진입점과 단계 순서는 동일하지만 옵션이 다른 경우 경고를 남깁니다.
 */
public class DuplicateMfaFlowValidator implements Validator<List<FlowContext>> {

    private static final Logger log = LoggerFactory.getLogger(DuplicateMfaFlowValidator.class);

    @Override
    public ValidationResult validate(List<FlowContext> flows) {

        if (flows == null || flows.isEmpty()) {
            return new ValidationResult();
//            throw new DslValidationException("검증할 FlowContext 목록이 비어 있습니다.");
        }

        ValidationResult result = new ValidationResult();

        // 모든 FlowContext 에서 MFA 흐름을 수집
        List<AuthenticationFlowConfig> allMfaFlows = flows.stream()
                .map(FlowContext::config)
                .flatMap(config -> config.getFlows().stream())
                .filter(flow -> "mfa".equalsIgnoreCase(flow.getTypeName()))
                .toList();

        // entryUrl + 단계 순서별 그룹핑
        Map<String, List<AuthenticationFlowConfig>> groups = allMfaFlows.stream()
                .collect(Collectors.groupingBy(this::entryStepsKey, LinkedHashMap::new, Collectors.toList()));

        // 그룹별 검사
        for (Map.Entry<String, List<AuthenticationFlowConfig>> entry : groups.entrySet()) {
            List<AuthenticationFlowConfig> sameGroup = entry.getValue();
            if (sameGroup.size() < 2) {
                continue;  // 중복 대상 아님
            }

            // 옵션까지 동일한 하위 그룹(fp) 생성
            Map<String, List<AuthenticationFlowConfig>> byFingerprint = sameGroup.stream()
                    .collect(Collectors.groupingBy(this::fingerprint, LinkedHashMap::new, Collectors.toList()));

            // 완전 중복(옵션까지 동일) → 오류
            for (Map.Entry<String, List<AuthenticationFlowConfig>> fpEntry : byFingerprint.entrySet()) {
                if (fpEntry.getValue().size() > 1) {
                    result.addError("중복된 MFA 흐름이 발견되었습니다: " + fpEntry.getKey());
                }
            }
            // 옵션만 차이 → 경고
            if (byFingerprint.size() > 1) {
                log.warn("유사한 MFA 흐름이 발견되었습니다 (옵션 차이): {}", entry.getKey());
            }
        }

        // 오류 존재 시 예외
        if (result.hasErrors()) {
            throw new DslValidationException("DuplicateMfaFlowValidator 오류:\n" + String.join("\n", result.getErrors()));
        }

        return result;
    }

    /** 진입점 + 단계 순서로 그룹핑 키 생성 */
    private String entryStepsKey(AuthenticationFlowConfig flow) {
        String steps = flow.getStepConfigs().stream()
                .map(AuthenticationStepConfig::getType)
                .collect(Collectors.joining("->"));
        return "|" + steps;
    }

    /** entryStepsKey + 옵션 요약으로 fingerprint 생성 */
    private String fingerprint(AuthenticationFlowConfig flow) {
        String base = entryStepsKey(flow);
        String opts = summarizeOptions(flow);
        return base + "|" + opts;
    }

    /** 주요 옵션들(retryPolicy, adaptiveConfig, deviceTrust, recoveryConfig)을 요약 */
    private String summarizeOptions(AuthenticationFlowConfig flow) {
        Map<String,String> map = new TreeMap<>();
        if (flow.getDefaultRetryPolicy() != null) {
            map.put("retryMax", String.valueOf(flow.getDefaultRetryPolicy().getMaxAttempts()));
        }
        if (flow.getDefaultAdaptiveConfig() != null) {
            map.put("adaptiveGeo", String.valueOf(flow.getDefaultAdaptiveConfig().geolocation()));
            map.put("adaptivePosture", String.valueOf(flow.getDefaultAdaptiveConfig().devicePosture()));
        }
        map.put("deviceTrust", String.valueOf(flow.isDefaultDeviceTrustEnabled()));
        return map.entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue())
                .collect(Collectors.joining(","));
    }
}

