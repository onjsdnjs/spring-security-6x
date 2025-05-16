package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.context.FlowContext;

import java.util.List;

public class DslSemanticValidator implements Validator<List<FlowContext>> {
    @Override
    public ValidationResult validate(List<FlowContext> flows)  {
        return new ValidationResult();
    }
}

