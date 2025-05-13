package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.context.FlowContext;

import java.util.List;

/**
 * DSL 문법 수준 검증
 */
public class DslSyntaxValidator implements Validator<List<FlowContext>> {
    @Override
    public ValidationResult validate(List<FlowContext> flows) {
        return new ValidationResult();
    }
}

