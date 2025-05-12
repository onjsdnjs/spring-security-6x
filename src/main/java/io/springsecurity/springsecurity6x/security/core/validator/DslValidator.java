package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;

import java.util.List;

/**
 * 복합 Validator: 여러 Validator를 순차 실행
 */
public class DslValidator implements Validator {
    private final List<Validator> delegates;

    public DslValidator(List<Validator> delegates) {
        this.delegates = delegates;
    }

    @Override
    public ValidationResult validate(PlatformConfig config) {
        ValidationResult result = new ValidationResult();
        for (Validator v : delegates) {
            ValidationResult r = v.validate(config);
            r.getErrors().forEach(result::addError);
            r.getWarnings().forEach(result::addWarning);
        }
        return result;
    }
}

