package io.springsecurity.springsecurity6x.security.core.validator;

import lombok.extern.slf4j.Slf4j;


/**
 * 검증 결과를 보고 예외를 던지거나 리포트하는 유틸리티
 */
@Slf4j
public class ValidationReportReporter {
    public static void report(ValidationResult result) {
       /* if (!result.isValid()) {
            String joined = String.join("\n", result.getErrors());
            throw new IllegalStateException("DSL 검증 실패:\n" + joined);
        }*/
    }
}

