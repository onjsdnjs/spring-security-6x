package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;


import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.MfaDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.validator.DslValidator;
import io.springsecurity.springsecurity6x.security.core.validator.ValidationReportReporter;
import io.springsecurity.springsecurity6x.security.core.validator.ValidationResult;

public class DslValidationConfigurer implements SecurityConfigurer {
    private final DslValidator validator;
    private final ValidationReportReporter reporter;

    public DslValidationConfigurer(DslValidator validator,
                                   ValidationReportReporter reporter) {
        this.validator        = validator;
        this.reporter         = reporter;
    }

    @Override
    public void init(PlatformContext context, PlatformConfig config) throws Exception {
        ValidationResult result = validator.validate(config);
        reporter.report(result);
        if (result.hasCritical()) {
            throw new IllegalStateException("DSL Validation failed: " + result.getErrors());
        }
    }

    @Override
    public void configure(FlowContext flowContext) throws Exception {

    }

    @Override
    public int getOrder() {
        return 50;  // DSL 검증 + 확장은 가장 먼저
    }
}

