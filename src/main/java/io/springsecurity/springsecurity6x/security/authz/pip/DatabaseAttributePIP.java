package io.springsecurity.springsecurity6x.security.authz.pip;

import io.springsecurity.springsecurity6x.repository.UserRepository;
import io.springsecurity.springsecurity6x.security.authz.context.AuthorizationContext;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class DatabaseAttributePIP implements AttributeInformationPoint {

    private final UserRepository userRepository;

    @Override
    public Map<String, Object> getAttributes(AuthorizationContext context) {
        Map<String, Object> attributes = new HashMap<>();

        // 사용자 속성 조회
        if (context.subject() != null) {
            userRepository.findByUsername(context.subject().getName()).ifPresent(user -> {
                attributes.put("username", user.getUsername());
                // 필요시 다른 사용자 속성(부서, 직책 등) 추가
            });
        }
        return attributes;
    }
}
