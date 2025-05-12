package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;

public class ConflictRiskAnalyzer implements Validator {
    @Override
    public ValidationResult validate(PlatformConfig config) {
        ValidationResult result = new ValidationResult();
        // TODO: DSL 설정 간 충돌 검사 (예: 동일 URL 중복 정의 등)
        return result;
    }
}

