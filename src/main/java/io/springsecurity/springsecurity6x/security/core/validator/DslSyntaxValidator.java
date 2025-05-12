package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;

public class DslSyntaxValidator implements Validator {
    @Override
    public ValidationResult validate(PlatformConfig config) {
        ValidationResult result = new ValidationResult();
        // TODO: 실제 DSL 구문 검사 로직
        // 예시:
        // if (config.getFlows().isEmpty()) result.addError("플로우 정의가 없습니다.");
        return result;
    }
}

