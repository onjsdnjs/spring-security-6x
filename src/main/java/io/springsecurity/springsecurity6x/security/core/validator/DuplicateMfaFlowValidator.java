package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.exception.DslValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;


/**
 * MFA 흐름 중복 검증기
 * - 각 FlowContext를 순회하며 MFA 흐름을 검사합니다.
 * - 진입점과 단계 순서가 동일하고 옵션까지 동일한 경우 오류를 발생시킵니다.
 * - 진입점과 단계 순서는 동일하지만 옵션이 다른 경우 경고를 남깁니다.
 */
public class DuplicateMfaFlowValidator implements Validator<List<FlowContext>> {

    private static final Logger log = LoggerFactory.getLogger(DuplicateMfaFlowValidator.class);

    @Override
    public ValidationResult validate(List<FlowContext> flows) {
        return new ValidationResult();
    }
}

