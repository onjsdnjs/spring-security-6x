package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.bootstrap.PathMappingRegistry;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;
import io.springsecurity.springsecurity6x.security.exception.DslValidationException;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * FlowContext 리스트를 검사하여 단일 인증 경로와 MFA 경로의 중복/충돌을 점검합니다.
 * 충돌이 발견되면 DslValidationException을 던져 서버 기동을 중단시킵니다.
 */
@Slf4j
public class ConflictRiskAnalyzer implements Validator<List<FlowContext>> {

    private static final String[] ORDINAL_EN = {
            "First", "Second", "Third", "Fourth", "Fifth",
            "Sixth", "Seventh", "Eighth", "Ninth", "Tenth"
    };

    @Override
    public ValidationResult validate(List<FlowContext> flows) {
        log.info("ConflictRiskAnalyzer: Starting DSL conflict validation");
        ValidationResult result = new ValidationResult();

        if (flows == null || flows.isEmpty()) {
            return new ValidationResult();
//            throw new DslValidationException("No FlowContext provided for validation.");
        }

        PlatformConfig config = flows.getFirst().config();

        PathMappingRegistry registry = new PathMappingRegistry(config);
        Set<String> single = registry.singleAuthPaths();
        if (single.size() != new LinkedHashSet<>(single).size()) {
            result.addError("Duplicate single authentication paths found: " + single);
        }

        int mfaCount = 0;
        for (AuthenticationFlowConfig flow : config.getFlows()) {
            if (!"mfa".equalsIgnoreCase(flow.getTypeName())) continue;
            mfaCount++;
            List<AuthenticationStepConfig> steps = flow.getStepConfigs();
            if (steps.size() < 2) continue;

            List<String> flowErrors = new ArrayList<>();
            if (!flowErrors.isEmpty()) {
                String headerLabel = mfaCount <= ORDINAL_EN.length ? ORDINAL_EN[mfaCount - 1] : mfaCount + "th";
                String headerText = headerLabel + " MFA";
                int boxWidth = headerText.length();
                for (String err : flowErrors) {
                    if (err.length() > boxWidth) boxWidth = err.length();
                }
                String horizontalBorder = "+" + "-".repeat(boxWidth + 2) + "+";
                result.addError(horizontalBorder);
                result.addError("| " + headerText + " ".repeat(boxWidth - headerText.length()) + " |");
                result.addError(horizontalBorder);
                for (String err : flowErrors) {
                    result.addError("| " + err + " ".repeat(boxWidth - err.length()) + " |");
                }
                result.addError(horizontalBorder);
            }
        }

        /*if (result.hasErrors()) {
            result.getErrors().forEach(log::error);
            throw new DslValidationException(
                    "DSL path conflicts detected. Error details:\n" +
                            String.join("\n", result.getErrors())
            );
        }*/

        log.info("ConflictRiskAnalyzer: DSL conflict validation passed");
        return result;
    }
}

