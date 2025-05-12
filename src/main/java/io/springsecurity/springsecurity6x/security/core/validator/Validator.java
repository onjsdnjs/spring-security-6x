package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;

/**
 * 제네릭 Validator 인터페이스
 */
public interface Validator<T> {
    ValidationResult validate(T target) throws Exception;
}

