package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;


import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.validator.*;

import java.util.List;

public class DslValidationConfigurer implements SecurityConfigurer {
    private final DslValidator validator;
    private final List<FlowContext> flows;

    public DslValidationConfigurer(DslValidator validator, List<FlowContext> flows) {
        this.validator =validator;
        this.flows = flows;
    }

    @Override
    public void init(PlatformContext context, PlatformConfig config) {
        ValidationResult result = validator.validate(flows);
        ValidationReportReporter.report(result);
    }

    @Override
    public void configure(FlowContext flowContext) throws Exception {
        // 검증만 수행하므로 빈 구현
    }

    @Override
    public int getOrder() {
        return Integer.MIN_VALUE;
    }
}

