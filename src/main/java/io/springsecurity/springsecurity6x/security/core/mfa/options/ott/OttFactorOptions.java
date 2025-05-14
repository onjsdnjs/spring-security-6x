package io.springsecurity.springsecurity6x.security.core.mfa.options.ott;

import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.ott.OneTimeTokenService;

@Setter
@Getter
public class OttFactorOptions extends FactorAuthenticationOptions {
    private OneTimeTokenService oneTimeTokenService; // Spring Security의 OneTimeTokenService
    private String tokenGeneratingUrl; // OTT 코드/링크 생성 요청 URL

    public OttFactorOptions() {
        super(AuthType.OTT);
    }
}
