package io.springsecurity.springsecurity6x.security.converter;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.List;

/**
 * 토큰 스트링을 Authentication 으로 변환하는 인터페이스
 */
public interface AuthenticationConverter {

     /**
      * 액세스 토큰으로부터 Authentication 객체를 생성합니다.
      */
     Authentication getAuthentication(String token);

     /**
      * 리프레시 토큰에서 역할 목록만 추출할 때 사용합니다.
      */
     List<String> getRoles(String token);
}