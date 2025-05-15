package io.springsecurity.springsecurity6x.security.core.mfa.options;

import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import lombok.Getter;
import org.springframework.util.Assert;

@Getter
public final class PrimaryAuthenticationOptions {
    private final FormOptions formOptions;
    private final RestOptions restOptions;
    private final String loginProcessingUrl;

    private PrimaryAuthenticationOptions(Builder builder) {
        this.formOptions = builder.formOptions;
        this.restOptions = builder.restOptions;
        this.loginProcessingUrl = builder.loginProcessingUrl;

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
            this.restOptions = null;
            if (formOptions != null) {
                this.loginProcessingUrl = formOptions.getLoginProcessingUrl();
            }
            return this;
        }

        public Builder restOptions(RestOptions restOptions) {
            this.restOptions = restOptions;
            this.formOptions = null;
            if (restOptions != null) {
                this.loginProcessingUrl = restOptions.getLoginProcessingUrl();
            }
            return this;
        }

        // loginProcessingUrl을 직접 설정할 수도 있지만, Form/Rest Options 에서 가져오는 것이 일반적
        public Builder loginProcessingUrl(String loginProcessingUrl) {
            this.loginProcessingUrl = loginProcessingUrl;
            return this;
        }

        public PrimaryAuthenticationOptions build() {
            // loginProcessingUrl이 설정되었는지 최종 확인
            if (formOptions != null && loginProcessingUrl == null) {
                this.loginProcessingUrl = formOptions.getLoginProcessingUrl();
            } else if (restOptions != null && loginProcessingUrl == null) {
                this.loginProcessingUrl = restOptions.getLoginProcessingUrl();
            }
            Assert.hasText(loginProcessingUrl, "loginProcessingUrl could not be determined from FormOptions or RestOptions and was not set directly.");
            return new PrimaryAuthenticationOptions(this);
        }
    }
}
