package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.context.FlowContext;

import java.util.List;

/**
 * 통합 DSL Validator
 */
public class DslValidator implements Validator<List<FlowContext>> {
    private final List<Validator<List<FlowContext>>> validators;

    public DslValidator(List<Validator<List<FlowContext>>> validators) {
        this.validators = validators;
    }

    @Override
    public ValidationResult validate(List<FlowContext> flows) throws Exception {
        ValidationResult finalResult = new ValidationResult();
        for (Validator<List<FlowContext>> v : validators) {
            ValidationResult r = v.validate(flows);
            r.getErrors().forEach(finalResult::addError);
        }
        return finalResult;
    }
}

