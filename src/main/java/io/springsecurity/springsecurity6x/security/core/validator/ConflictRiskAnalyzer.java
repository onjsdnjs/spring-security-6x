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
            throw new DslValidationException("No FlowContext provided for validation.");
        }

        // Use shared PlatformConfig from first context
        PlatformConfig config = flows.get(0).config();

        // 1) Check duplicate single authentication paths
        PathMappingRegistry registry = new PathMappingRegistry(config);
        Set<String> single = registry.singleAuthPaths();
        if (single.size() != new LinkedHashSet<>(single).size()) {
            result.addError("Duplicate single authentication paths found: " + single);
        }

        // 2) Validate each MFA flow's targetUrl (skip first step)
        int mfaCount = 0;
        for (AuthenticationFlowConfig flow : config.flows()) {
            if (!"mfa".equalsIgnoreCase(flow.typeName())) continue;
            mfaCount++;
            List<AuthenticationStepConfig> steps = flow.stepConfigs();
            if (steps.size() < 2) continue;

            List<String> flowErrors = new ArrayList<>();
            for (int i = 1; i < steps.size(); i++) {
                AuthenticationStepConfig step = steps.get(i);
                Object opts = step.options().get("_options");
                String type = step.type();
                String url = null;
                if (opts instanceof FormOptions) {
                    url = ((FormOptions) opts).getTargetUrl();
                } else if (opts instanceof OttOptions) {
                    url = ((OttOptions) opts).getTargetUrl();
                } else if (opts instanceof PasskeyOptions) {
                    url = ((PasskeyOptions) opts).getTargetUrl();
                }
                if (url == null || url.isBlank()) {
                    flowErrors.add("MFA step '" + type + "' has no targetUrl set.");
                }
            }
            if (!flowErrors.isEmpty()) {
                String headerLabel = mfaCount <= ORDINAL_EN.length ? ORDINAL_EN[mfaCount - 1] : mfaCount + "th";
                String headerText = headerLabel + " MFA";
                // Calculate box width
                int boxWidth = headerText.length();
                for (String err : flowErrors) {
                    if (err.length() > boxWidth) boxWidth = err.length();
                }
                String horizontalBorder = "+" + "-".repeat(boxWidth + 2) + "+";
                // Top border and header
                result.addError(horizontalBorder);
                result.addError("| " + headerText + " ".repeat(boxWidth - headerText.length()) + " |");
                result.addError(horizontalBorder);
                // Error lines
                for (String err : flowErrors) {
                    result.addError("| " + err + " ".repeat(boxWidth - err.length()) + " |");
                }
                // Bottom border
                result.addError(horizontalBorder);
            }
        }

        // 3) Final result check
        if (result.hasErrors()) {
            result.getErrors().forEach(log::error);
            throw new DslValidationException(
                    "DSL path conflicts detected. Error details:\n" +
                            String.join("\n", result.getErrors())
            );
        }

        log.info("ConflictRiskAnalyzer: DSL conflict validation passed");
        return result;
    }
}

