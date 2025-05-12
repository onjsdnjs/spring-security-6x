package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;

/**
 * DSL 의미론 수준 검증
 * - 인증방식이 2개 이상이면 반드시 securityMatcher 설정
 */
public class DslSemanticValidator implements Validator<List<FlowContext>> {
    @Override
    public ValidationResult validate(List<FlowContext> flows) throws Exception {
        ValidationResult result = new ValidationResult();
        if (flows.size() >= 2) {
            for (FlowContext fc : flows) {
                DefaultSecurityFilterChain dsc = fc.http().build();
                RequestMatcher matcher = dsc.getRequestMatcher();
                if (matcher == null) {
                    result.addError(
                            "Flow '" + fc.flow().typeName() + "' 에 securityMatcher 가 설정되지 않았습니다."
                    );
                }
            }
        }
        return result;
    }
}

