package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;

import java.util.List;

public class DslValidator {
    private final List<Validator> validators;

    public DslValidator(List<Validator> validators) {
        this.validators = validators;
    }

    public ValidationResult validate(PlatformConfig config) {
        ValidationResult result = new ValidationResult();
        for (Validator v : validators) {
            ValidationResult r = v.validate(config);
            r.getErrors().forEach(result::addError);
            r.getWarnings().forEach(result::addWarning);
        }
        return result;
    }
}

