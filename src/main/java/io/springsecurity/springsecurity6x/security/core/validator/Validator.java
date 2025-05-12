package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;

public interface Validator {
    ValidationResult validate(PlatformConfig config);
}

