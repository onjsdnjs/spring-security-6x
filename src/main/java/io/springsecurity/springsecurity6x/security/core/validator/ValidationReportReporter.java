package io.springsecurity.springsecurity6x.security.core.validator;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ValidationReportReporter {

    public void report(ValidationResult result) {
        if (result.hasErrors()) {
            log.error("DSL Validation Errors: {}", result.getErrors());
            System.err.println("DSL Validation Errors: " + result.getErrors());
        }
        if (!result.getWarnings().isEmpty()) {
            log.warn("DSL Validation Warnings: {}", result.getWarnings());
            System.out.println("DSL Validation Warnings: " + result.getWarnings());
        }
    }
}

