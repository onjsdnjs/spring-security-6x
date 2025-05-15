package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.validator.*;
import io.springsecurity.springsecurity6x.security.exception.DslValidationException;
import org.springframework.beans.factory.annotation.Autowired; // 스프링을 사용한다면
import org.springframework.stereotype.Service; // 스프링을 사용한다면

import java.util.List;

/**
 * DSL(Domain Specific Language) 정의의 유효성을 검사하는 서비스입니다.
 * 다양한 Validator 구현체들을 사용하여 FlowContext 목록을 검증하고 결과를 리포팅합니다.
 */
public class DslValidatorService {

    private final DslValidator dslValidator;
    public DslValidatorService(DslValidator dslValidator) {
        this.dslValidator = dslValidator;
    }


    /**
     * 제공된 FlowContext 목록에 대해 DSL 유효성 검사를 수행합니다.
     * 검증 결과는 ValidationReportReporter를 통해 리포팅됩니다.
     *
     * @param flows 검증할 FlowContext 목록
     * @throws DslValidationException 유효성 검사 실패 시 발생 (선택적: 필요에 따라 커스텀 예외 정의)
     */
    public void validate(List<FlowContext> flows) {
        if (flows == null || flows.isEmpty()) {
            // 검증 대상이 없는 경우, 로깅 또는 조기 반환
            // log.info("DSL 검증 대상 Flow가 없습니다.");
            return;
        }

        ValidationResult result = dslValidator.validate(flows);
        ValidationReportReporter.report(result); // 기존 리포팅 방식 활용

        // 유효성 검사 결과에 따라 예외를 발생시킬 수 있습니다.
        // 예를 들어, 심각한 오류가 있을 경우 초기화를 중단시키기 위함입니다.
        /*if (result.hasErrors() || result.hasErrors()) {
            // log.error("DSL 유효성 검사 실패. 상세 내용은 이전 로그를 확인하세요.");
             throw new DslValidationException("DSL 유효성 검사에 실패했습니다.: " + result.getErrors()); // 커스텀 예외
        }*/
    }
}
