package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

@Slf4j
public class ConflictRiskAnalyzer implements Validator<List<FlowContext>> {

    @Override
    public ValidationResult validate(List<FlowContext> flows) {
        return new ValidationResult();
    }
}

