package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;

public class DslSemanticValidator implements Validator {
    @Override
    public ValidationResult validate(PlatformConfig config) {
        ValidationResult result = new ValidationResult();
        // TODO: 의미 검사 (중복 스텝, 잘못된 참조 등)
        return result;
    }
}

