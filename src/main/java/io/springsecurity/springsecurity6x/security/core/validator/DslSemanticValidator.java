package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;

/**
 * DSL 의미(semantic) 오류 검사
 */
public class DslSemanticValidator implements Validator {
    @Override
    public ValidationResult validate(PlatformConfig config) {
        ValidationResult result = new ValidationResult();

        // 예: stateConfig가 null 이면 경고
        for (AuthenticationFlowConfig flow : config.flows()) {
            if (flow.stateConfig() == null) {
                result.addWarning(
                        String.format("Flow '%s'에 상태 전략(stateConfig)이 설정되지 않았습니다. Default가 적용됩니다.",
                                flow.typeName()));
            }
        }
        return result;
    }
}

