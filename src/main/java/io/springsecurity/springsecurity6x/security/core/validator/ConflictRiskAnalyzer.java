package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * DSL 설정 간 충돌 검사 (예: 중복된 MFA 조합)
 */
public class ConflictRiskAnalyzer implements Validator {
    @Override
    public ValidationResult validate(PlatformConfig config) {

        ValidationResult result = new ValidationResult();
        Set<String> seen = new HashSet<>();
        for (AuthenticationFlowConfig flow : config.flows()) {
            if (!"mfa".equalsIgnoreCase(flow.typeName())) {
                continue;
            }
            String stepsSignature = flow.stepConfigs().stream()
                    .map(AuthenticationStepConfig::type)
                    .collect(Collectors.joining(">"));
            String state = flow.stateConfig() != null
                    ? flow.stateConfig().state()
                    : "";
            String signature = stepsSignature + "|" + state;
            if (!seen.add(signature)) {
                result.addError(
                        String.format("중복된 MFA 조합이 탐지되었습니다: [%s]", signature)
                );
            }
        }
        return result;
    }
}

