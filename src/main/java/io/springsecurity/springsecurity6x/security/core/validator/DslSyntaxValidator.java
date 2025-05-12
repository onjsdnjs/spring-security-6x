package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.context.FlowContext;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * DSL 문법 수준 검증
 */
public class DslSyntaxValidator implements Validator<List<FlowContext>> {
    @Override
    public ValidationResult validate(List<FlowContext> flows) {
        ValidationResult result = new ValidationResult();
        Set<String> names = new HashSet<>();
        for (FlowContext fc : flows) {
            String name = fc.flow().typeName();
            if (!names.add(name)) {
                result.addError("중복된 flow 이름이 있습니다: " + name);
            }
        }
        return result;
    }
}

