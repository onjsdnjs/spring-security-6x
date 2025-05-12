package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;

/**
 * DSL 문법(syntax) 오류 검사
 */
public class DslSyntaxValidator implements Validator {
    @Override
    public ValidationResult validate(PlatformConfig config) {
        ValidationResult result = new ValidationResult();

        // 예: 각 FlowConfig에 스텝이 1개 이상 정의되어야 함
        for (AuthenticationFlowConfig flow : config.flows()) {
            if (flow.stepConfigs().isEmpty()) {
                result.addError(
                        String.format("Flow '%s'에 인증 스텝이 정의되어 있지 않습니다.", flow.typeName()));
            }
        }
        return result;
    }
}

