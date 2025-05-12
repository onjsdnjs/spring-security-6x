package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;
import java.util.Objects;

/**
 * RequestMatcher 충돌 위험 분석
 * - 동일 패턴, 상위/하위 경로 중복
 */
public class ConflictRiskAnalyzer implements Validator<List<FlowContext>> {
    @Override
    public ValidationResult validate(List<FlowContext> flows) {
        List<RequestMatcher> matchers = flows.stream()
                .map(fc -> {
                    DefaultSecurityFilterChain dsc = null;
                    try {
                        dsc = fc.http().build();
                        return dsc.getRequestMatcher();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                })
                .filter(Objects::nonNull)
                .toList();
        ValidationResult result = new ValidationResult();
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
        }
        return result;
    }
}

