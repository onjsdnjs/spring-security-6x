package io.springsecurity.springsecurity6x.security.authz.service;

import io.springsecurity.springsecurity6x.domain.dto.PolicyDto;
import io.springsecurity.springsecurity6x.entity.policy.*;
import io.springsecurity.springsecurity6x.repository.PolicyRepository;
import io.springsecurity.springsecurity6x.security.authz.manager.CustomDynamicAuthorizationManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
@Transactional
public class DefaultPolicyService implements PolicyService {

    private final PolicyRepository policyRepository;
    private final PolicyRetrievalPoint policyRetrievalPoint;
    private final CustomDynamicAuthorizationManager authorizationManager;

    @Override
    @Transactional(readOnly = true)
    public List<Policy> getAllPolicies() {
        return policyRepository.findAll();
    }

    @Override
    @Transactional(readOnly = true)
    public Policy findById(Long id) {
        return policyRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Policy not found with ID: " + id));
    }

    @Override
    public Policy createPolicy(PolicyDto policyDto) {
        Policy policy = convertDtoToEntity(policyDto);
        Policy savedPolicy = policyRepository.save(policy);

        reloadAuthorizationSystem();
        log.info("Policy created and authorization system reloaded. Policy Name: {}", savedPolicy.getName());
        return savedPolicy;
    }

    @Override
    public Policy updatePolicy(PolicyDto policyDto) {
        Policy existingPolicy = findById(policyDto.getId());
        // DTO의 내용으로 기존 엔티티 업데이트 (ID, 관계 등은 유지)
        updateEntityFromDto(existingPolicy, policyDto);
        Policy updatedPolicy = policyRepository.save(existingPolicy);

        reloadAuthorizationSystem();
        log.info("Policy updated and authorization system reloaded. Policy ID: {}", updatedPolicy.getId());
        return updatedPolicy;
    }

    @Override
    public void deletePolicy(Long id) {
        policyRepository.deleteById(id);
        reloadAuthorizationSystem();
        log.info("Policy deleted and authorization system reloaded. Policy ID: {}", id);
    }

    /**
     * 정책 변경 후 인가 시스템을 다시 로드하는 중앙화된 메서드.
     */
    private void reloadAuthorizationSystem() {
        policyRetrievalPoint.clearUrlPoliciesCache(); // PRP 캐시 무효화
        authorizationManager.reload(); // PEP가 규칙을 다시 로드하도록 함
    }

    // --- DTO <-> Entity 변환 헬퍼 메서드 ---
    private Policy convertDtoToEntity(PolicyDto dto) {
        Policy policy = Policy.builder()
                .name(dto.getName())
                .description(dto.getDescription())
                .effect(dto.getEffect())
                .priority(dto.getPriority())
                .build();

        Set<PolicyTarget> targets = dto.getTargets().stream().map(t -> {
            String[] parts = t.split(":", 2);
            return PolicyTarget.builder().policy(policy).targetType(parts[0]).targetIdentifier(parts[1]).build();
        }).collect(Collectors.toSet());

        PolicyRule rule = PolicyRule.builder().policy(policy).description("Main rule for " + dto.getName()).build();
        Set<PolicyCondition> conditions = dto.getConditions().stream()
                .map(c -> PolicyCondition.builder().rule(rule).expression(c).build())
                .collect(Collectors.toSet());

        rule.setConditions(conditions);
        policy.setTargets(targets);
        policy.setRules(Set.of(rule));

        return policy;
    }

    private void updateEntityFromDto(Policy policy, PolicyDto dto) {
        policy.setName(dto.getName());
        policy.setDescription(dto.getDescription());
        policy.setEffect(dto.getEffect());
        policy.setPriority(dto.getPriority());

        // Target, Rule, Condition은 복잡하므로 여기서는 단순화를 위해 clear and add all 전략 사용
        policy.getTargets().clear();
        policy.getRules().clear();

        Set<PolicyTarget> targets = dto.getTargets().stream().map(t -> {
            String[] parts = t.split(":", 2);
            return PolicyTarget.builder().policy(policy).targetType(parts[0]).targetIdentifier(parts[1]).build();
        }).collect(Collectors.toSet());

        PolicyRule rule = PolicyRule.builder().policy(policy).description("Main rule for " + dto.getName()).build();
        Set<PolicyCondition> conditions = dto.getConditions().stream()
                .map(c -> PolicyCondition.builder().rule(rule).expression(c).build())
                .collect(Collectors.toSet());

        rule.setConditions(conditions);
        policy.setTargets(targets);
        policy.setRules(Set.of(rule));
    }
}
