package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.bootstrap.PathMappingRegistry;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.exception.DslValidationException;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * FlowContext 리스트를 검사하여 단일 인증 경로와 MFA 경로의 중복/충돌을 점검합니다.
 * 충돌이 발견되면 DslValidationException을 던져 서버 기동을 중단시킵니다.
 */
@Slf4j
public class ConflictRiskAnalyzer implements Validator<List<FlowContext>> {

    @Override
    public ValidationResult validate(List<FlowContext> flows) {

        log.info("ConflictRiskAnalyzer: DSL 충돌 검사 시작");
        ValidationResult result = new ValidationResult();

        // DSL 전체 PlatformConfig는 FlowContext 에서 공유 객체로 취득
        PlatformConfig config = flows.getFirst().config();
        PathMappingRegistry registry = new PathMappingRegistry(config);

        // 1) 단일 인증 경로 중복 검사
        Set<String> single = registry.singleAuthPaths();
        if (single.size() != new HashSet<>(single).size()) {
            result.addError("단일 인증 경로에 중복이 있습니다: " + single);
        }

        // 2) MFA 진입점 중복 검사
        Set<String> entries = registry.mfaEntryPaths();
        if (entries.isEmpty()) {
            result.addError("MFA 진입점이 하나도 설정되어 있지 않습니다.");
        }
        if (entries.size() > 1) {
            result.addError("MFA 진입점이 여러 개 설정되어 있습니다: " + entries);
        }

        // 3) MFA 단계별 엔드포인트 중복 검사
        Map<String,String> steps = registry.mfaStepPaths();
        if (steps.size() != new LinkedHashSet<>(steps.keySet()).size()) {
            result.addError("MFA 단계별 경로에 중복이 있습니다: " + steps.keySet());
        }

        // 4) 단일 vs MFA 경로 충돌
        for (String p : single) {
            if (entries.contains(p) || steps.containsKey(p)) {
                result.addError("단일 인증 경로와 MFA 경로 충돌: " + p);
            }
        }

        // 결과 확인
        if (result.hasErrors()) {
            for (String err : result.getErrors()) {
                log.error(err);
            }
            throw new DslValidationException("DSL 경로 충돌이 발견되었습니다. 상세 로그를 확인하세요.");
        }

        log.info("ConflictRiskAnalyzer: DSL 충돌 검사 통과");
        return result;
    }
}

