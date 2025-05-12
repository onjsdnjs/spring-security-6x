package io.springsecurity.springsecurity6x.security.core.validator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ValidationReportReporter {
    private static final Logger log = LoggerFactory.getLogger(ValidationReportReporter.class);

    public void report(ValidationResult result) {
        if (result.hasErrors()) {
            log.error("DSL Validation Errors: {}", result.getErrors());
        }
        if (!result.getWarnings().isEmpty()) {
            log.warn("DSL Validation Warnings: {}", result.getWarnings());
        }
        // 콘솔에도 출력
        System.out.println("[DSL Validation] " + result.toJson());
    }
}

