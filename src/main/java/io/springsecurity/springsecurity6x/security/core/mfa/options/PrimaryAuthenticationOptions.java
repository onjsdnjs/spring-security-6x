package io.springsecurity.springsecurity6x.security.core.mfa.options;

import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import lombok.Getter;
import org.springframework.util.Assert;

/**
 * MFA 플로우의 1차 인증(ID/PW)에 대한 기술적 설정을 담는 불변 객체입니다.
 * Form 방식 또는 REST 방식 중 하나를 포함할 수 있습니다.
 */
@Getter
public final class PrimaryAuthenticationOptions {

    private final FormOptions formOptions;
    private final RestOptions restOptions;
    private final String loginProcessingUrl; // 1차 인증 요청을 처리하는 URL

    private PrimaryAuthenticationOptions(Builder builder) {
        this.formOptions = builder.formOptions;
        this.restOptions = builder.restOptions;
        this.loginProcessingUrl = builder.loginProcessingUrl;

        // Form 또는 Rest 중 하나는 반드시 설정되어야 함
        Assert.isTrue(formOptions != null || restOptions != null,
                "Either FormOptions or RestOptions must be configured for primary authentication.");
        Assert.isTrue(formOptions == null || restOptions == null,
                "Cannot configure both FormOptions and RestOptions for primary authentication.");
        Assert.hasText(loginProcessingUrl, "loginProcessingUrl must be set for primary authentication.");
    }

    public boolean isFormLogin() {
        return formOptions != null;
    }

    public boolean isRestLogin() {
        return restOptions != null;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private FormOptions formOptions;
        private RestOptions restOptions;
        private String loginProcessingUrl;

        public Builder formOptions(FormOptions formOptions) {
            this.formOptions = formOptions;
            this.restOptions = null; // 상호 배타적
            return this;
        }

        public Builder restOptions(RestOptions restOptions) {
            this.restOptions = restOptions;
            this.formOptions = null; // 상호 배타적
            return this;
        }

        public Builder loginProcessingUrl(String loginProcessingUrl) {
            this.loginProcessingUrl = loginProcessingUrl;
            return this;
        }

        public PrimaryAuthenticationOptions build() {
            return new PrimaryAuthenticationOptions(this);
        }
    }
}
