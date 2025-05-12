package io.springsecurity.springsecurity6x.security.core.validator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 검증 결과를 담는 객체
 */
public class ValidationResult {
    private final List<String> errors;

    public ValidationResult() {
        this.errors = new ArrayList<>();
    }

    public void addError(String msg) {
        errors.add(msg);
    }

    public boolean isValid() {
        return errors.isEmpty();
    }

    public List<String> getErrors() {
        return Collections.unmodifiableList(errors);
    }
}


