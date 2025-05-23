package io.springsecurity.springsecurity6x.security.core.mfa.context;

import io.springsecurity.springsecurity6x.security.enums.AuthType;

import java.util.Set;

/**
 * FactorContext에 추가되어야 할 메서드들을 정의하는 인터페이스
 * 기존 FactorContext 클래스에 이 메서드들을 추가해야 함
 */
public interface FactorContextExtensions {

    /**
     * 재시도 횟수 조회
     * @return 현재까지의 재시도 횟수
     */
    int getRetryCount();

    /**
     * 재시도 횟수 설정
     * @param retryCount 설정할 재시도 횟수
     */
    void setRetryCount(int retryCount);

    /**
     * 사용 가능한 인증 팩터 목록 조회
     * @return 사용 가능한 팩터 목록
     */
    Set<AuthType> getAvailableFactors();

    /**
     * 완료된 인증 팩터 목록 조회
     * @return 완료된 팩터 목록
     */
    Set<AuthType> getCompletedFactors();

    /**
     * 마지막 에러 메시지 조회
     * @return 마지막 에러 메시지
     */
    String getLastError();

    /**
     * 마지막 에러 메시지 설정
     * @param error 에러 메시지
     */
    void setLastError(String error);

    /**
     * 컨텍스트 생성 시간 조회
     * @return 생성 시간 (epoch milliseconds)
     */
    long getCreatedAt();
}
