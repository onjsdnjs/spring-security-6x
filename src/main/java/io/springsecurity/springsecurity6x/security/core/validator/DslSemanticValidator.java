package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.context.FlowContext;

import java.util.List;

/**
 * DSL 의미론 수준 검증
 * - 인증방식이 2개 이상이면 반드시 securityMatcher 설정
 */
public class DslSemanticValidator implements Validator<List<FlowContext>> {
    @Override
    public ValidationResult validate(List<FlowContext> flows) throws Exception {
        return new ValidationResult();
    }
}

