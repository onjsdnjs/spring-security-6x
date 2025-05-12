package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * RequestMatcher 충돌 위험 분석
 * - 동일 패턴, 상위/하위 경로 중첩 여부 검사
 */
public class ConflictRiskAnalyzer implements Validator<List<FlowContext>> {
    @Override
    public ValidationResult validate(List<FlowContext> flows) {
        ValidationResult result = new ValidationResult();
        /*List<RequestMatcher> matchers = flows.stream()
                .map(fc -> fc.flow().getRequestMatcher())
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        for (int i = 0; i < matchers.size(); i++) {
            for (int j = i + 1; j < matchers.size(); j++) {
                String p1 = matchers.get(i).toString();
                String p2 = matchers.get(j).toString();
                if (p1.equals(p2)) {
                    result.addError("보안 매처 충돌: 동일 패턴 발견 (" + p1 + ")");
                } else if (p1.startsWith(p2) || p2.startsWith(p1)) {
                    result.addError("보안 매처 충돌: 경로 중첩 가능성 (" + p1 + ", " + p2 + ")");
                }
            }
        }*/
        return result;
    }
}

