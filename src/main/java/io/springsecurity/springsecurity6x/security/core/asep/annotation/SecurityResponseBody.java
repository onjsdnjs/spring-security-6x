package io.springsecurity.springsecurity6x.security.core.asep.annotation;

import org.springframework.web.bind.annotation.ResponseBody; // Spring의 ResponseBody 활용
import java.lang.annotation.*;

@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@ResponseBody // Spring의 HttpMessageConverter 선택 로직 등을 활용하기 위해 메타 어노테이션으로 사용
public @interface SecurityResponseBody {
}
