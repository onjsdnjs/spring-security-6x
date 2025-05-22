package io.springsecurity.springsecurity6x.security.core.validator;


import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext; // FlowContext import
import io.springsecurity.springsecurity6x.security.enums.AuthType; // AuthType Enum import
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Validates that there are no duplicate MFA flow configurations based on their unique names (typeName)
 * among the provided list of FlowContexts.
 *
 * It identifies MFA flows by checking the AuthType of the AuthenticationFlowConfig
 * obtained from each FlowContext. The uniqueness of MFA flows is checked based on their
 * {@link AuthenticationFlowConfig#getTypeName()}.
 */
public class DuplicateMfaFlowValidator implements Validator<List<FlowContext>> {

    private static final Logger log = LoggerFactory.getLogger(DuplicateMfaFlowValidator.class);

    @Override
    public ValidationResult validate(List<FlowContext> flowContexts) {
        ValidationResult result = new ValidationResult(); // ValidationResult 객체 생성

        if (CollectionUtils.isEmpty(flowContexts)) {
            log.debug("No FlowContexts provided to DuplicateMfaFlowValidator. Validation considered successful by default.");
            return result; // 오류가 없으므로 result는 기본적으로 유효함 (isValid()가 true 반환)
        }

        // 1. 모든 FlowContext에서 AuthenticationFlowConfig를 추출하고, MFA 플로우만 필터링합니다.
        // FlowContext.java에 getFlowConfig() 메소드가 존재하므로 이를 사용합니다.
        List<AuthenticationFlowConfig> mfaFlowConfigs = flowContexts.stream()
                .filter(Objects::nonNull) // Null FlowContext 방지
                .map(FlowContext::flow) // FlowContext 에서 AuthenticationFlowConfig 가져오기
                .filter(Objects::nonNull) // getFlowConfig()가 null을 반환할 경우를 대비
                .filter(this::isConsideredAsMfaFlow) // MFA 플로우인지 확인하는 헬퍼 메소드
                .collect(Collectors.toList());

        if (CollectionUtils.isEmpty(mfaFlowConfigs)) {
            log.debug("No MFA flows found among the provided FlowContexts. Duplicate MFA flow check is successful by default.");
            return result; // MFA 플로우가 없으면 중복도 없음
        }

        log.info("Starting validation for duplicate MFA flow names. Total MFA flows identified for check: {}", mfaFlowConfigs.size());

        Set<String> uniqueMfaFlowNormalizedTypeNames = new HashSet<>();
        Set<String> duplicateMfaFlowOriginalTypeNames = new HashSet<>();

        for (AuthenticationFlowConfig mfaFlow : mfaFlowConfigs) {
            String typeName = mfaFlow.getTypeName(); // AuthenticationFlowConfig에 getTypeName()이 있다고 가정
            if (!StringUtils.hasText(typeName)) {
                log.warn("An MFA AuthenticationFlowConfig (AuthType: {}) was found with a null or empty typeName (flow name). " +
                                "This entry will be skipped for duplicate check, but it might indicate a syntax/configuration issue.",
                        typeName != null ? typeName : "UNKNOWN");
                continue;
            }

            // MFA 플로우 이름의 고유성은 대소문자를 구분하지 않고 검사 (일반적인 관례 및 다른 곳에서의 비교 방식 고려)
            String normalizedTypeName = typeName.toLowerCase();

            if (!uniqueMfaFlowNormalizedTypeNames.add(normalizedTypeName)) {
                // Set.add()는 요소가 이미 존재하면 false를 반환 -> 중복 발견
                duplicateMfaFlowOriginalTypeNames.add(typeName); // 오류 보고를 위해 원본 typeName 기록
            }
        }

        if (!duplicateMfaFlowOriginalTypeNames.isEmpty()) {
            String duplicatesMessage = duplicateMfaFlowOriginalTypeNames.stream()
                    .distinct() // 중복된 이름 자체는 한 번만 오류 메시지에 포함
                    .map(name -> "'" + name + "'") // 각 이름을 작은따옴표로 감쌈
                    .collect(Collectors.joining(", "));
            String errorMessage = String.format(
                    "CRITICAL CONFIGURATION ERROR: Duplicate MFA AuthenticationFlowConfig typeName(s) (flow name) found: %s. " +
                            "Each MFA flow defined by .name() in your DSL (e.g., PlatformSecurityConfig) MUST have a unique name (case-insensitive for this check). " +
                            "Please review your security configuration to ensure all MFA flow names are unique to prevent runtime ambiguity.",
                    duplicatesMessage
            );
            log.error(errorMessage);
            result.addError(errorMessage); // ValidationResult에 오류 추가
        } else {
            log.info("Validation successful: All identified MFA AuthenticationFlowConfig typeNames are unique (case-insensitive).");
        }
        return result;
    }

    /**
     * 주어진 AuthenticationFlowConfig가 MFA 플로우로 간주될 수 있는지 확인하는 헬퍼 메소드입니다.
     * AuthenticationFlowConfig에 isMfaFlow()와 같은 명시적인 플래그가 있는 것이 가장 좋습니다.
     * 없다면, AuthType 또는 typeName 으로 추론합니다.
     *
     * @param flowConfig 확인할 AuthenticationFlowConfig
     * @return MFA 플로우로 간주되면 true, 그렇지 않으면 false
     */
    private boolean isConsideredAsMfaFlow(AuthenticationFlowConfig flowConfig) {
        if (flowConfig == null) {
            return false;
        }

        // 방법 1: AuthenticationFlowConfig에 isMfaFlow() 같은 명시적 메소드가 있다면 사용 (가장 좋음)
        // 제공된 AuthenticationFlowConfig.java 파일에 isMfaFlow() 가 있는지 확인 필요.
        // 현재 AuthenticationFlowConfig.java 파일 내용을 알 수 없으므로, getAuthType()을 우선 사용합니다.
        // if (flowConfig.isMfaFlow()) {
        //     return true;
        // }

        // 방법 2: AuthType을 확인 (AuthenticationFlowConfig에 getAuthType()이 있고 AuthType Enum을 반환한다고 가정)
        AuthType authType = AuthType.valueOf(flowConfig.getTypeName()); // AuthenticationFlowConfig.java에 getAuthType() 존재 확인 필요
        if (authType == AuthType.MFA) {
            return true;
        }

        // 방법 3: typeName (flow name)으로 추론 (덜 정확할 수 있음, 최후의 수단)
        String typeName = flowConfig.getTypeName();
        if (StringUtils.hasText(typeName)) {
            String upperTypeName = typeName.toUpperCase();
            // "MFA" 자체이거나 "MFA_"로 시작하는 경우 MFA 플로우로 간주 (예: "MFA_FORM", "MFA_REST")
            if (upperTypeName.equals(AuthType.MFA.name()) || upperTypeName.startsWith(AuthType.MFA.name() + "_")) {
                log.debug("Flow '{}' is considered MFA flow by typeName convention.", typeName);
                return true;
            }
        }
        log.trace("Flow '{}' (AuthType: {}) is not considered an MFA flow by this validator's criteria.",
                flowConfig.getTypeName(), (authType != null ? authType.name() : "null"));
        return false;
    }

    /**
     * DslValidatorService에서 순서 관리를 위해 필요할 수 있는 getOrder() 메소드.
     * Validator<T> 인터페이스가 Ordered를 상속하거나, DslValidatorService가 @Order를 사용한다면
     * 이 메소드는 해당 규약에 맞게 조정되거나 불필요할 수 있습니다.
     * 여기서는 일반적인 경우를 가정하여 추가하며, 실제 프로젝트의 Validator 순서 관리 방식에 따라야 합니다.
     * @return the order of this validator
     */
    // @Override // 만약 Validator 인터페이스가 Ordered를 상속한다면
    public int getOrder() {
        // 다른 Validator들과의 실행 순서를 고려하여 적절한 값 설정
        // 예: 다른 구문 검사 이후, 하지만 너무 늦지 않은 시점에 실행
        return 120; // 예시 값 (ValidatorOrder 와 같은 상수 사용 권장)
    }
}

