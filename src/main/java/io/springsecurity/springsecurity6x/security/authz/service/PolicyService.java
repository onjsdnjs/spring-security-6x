package io.springsecurity.springsecurity6x.security.authz.service;

import io.springsecurity.springsecurity6x.domain.dto.PolicyDto;
import io.springsecurity.springsecurity6x.entity.policy.Policy;

import java.util.List;

/**
 * PAP (Policy Administration Point) 서비스 인터페이스.
 * 정책의 생성, 수정, 삭제 등 관리 책임을 갖는다.
 */
public interface PolicyService {
    List<Policy> getAllPolicies();
    Policy findById(Long id);
    Policy createPolicy(PolicyDto policyDto);
    Policy updatePolicy(PolicyDto policyDto);
    void deletePolicy(Long id);
}