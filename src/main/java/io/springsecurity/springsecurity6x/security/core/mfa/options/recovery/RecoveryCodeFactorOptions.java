package io.springsecurity.springsecurity6x.security.core.mfa.options.recovery;

import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.util.Assert;

public class RecoveryCodeFactorOptions extends FactorAuthenticationOptions {
    // private RecoveryCodeStore recoveryCodeStore; // 복구 코드 저장/검증 서비스
    private final int codeLength;
    private final int numberOfCodesToGenerate;

    // private 생성자로 변경, Builder를 통해서만 생성
    private RecoveryCodeFactorOptions(Builder builder) {
        super(builder, AuthType.RECOVERY_CODE); // 부모 생성자 호출
        // this.recoveryCodeStore = builder.recoveryCodeStore;
        this.codeLength = builder.codeLength;
        this.numberOfCodesToGenerate = builder.numberOfCodesToGenerate;
    }

    // Getter 메소드들
    // public RecoveryCodeStore getRecoveryCodeStore() { return recoveryCodeStore; }
    public int getCodeLength() {
        return codeLength;
    }
    public int getNumberOfCodesToGenerate() {
        return numberOfCodesToGenerate;
    }

    // static factory method for builder
    public static Builder builder() {
        return new Builder();
    }

    // Builder 내부 클래스 정의
    public static class Builder extends FactorAuthenticationOptions.AbstractFactorOptionsBuilder<RecoveryCodeFactorOptions, Builder> {
        // private RecoveryCodeStore recoveryCodeStore;
        private int codeLength = 8; // 기본값
        private int numberOfCodesToGenerate = 10; // 기본값

        /*
        public Builder recoveryCodeStore(RecoveryCodeStore recoveryCodeStore) {
            this.recoveryCodeStore = recoveryCodeStore;
            return this;
        }
        */

        public Builder codeLength(int codeLength) {
            Assert.isTrue(codeLength > 0, "codeLength must be positive");
            this.codeLength = codeLength;
            return this;
        }

        public Builder numberOfCodesToGenerate(int numberOfCodesToGenerate) {
            Assert.isTrue(numberOfCodesToGenerate > 0, "numberOfCodesToGenerate must be positive");
            this.numberOfCodesToGenerate = numberOfCodesToGenerate;
            return this;
        }

        @Override
        protected Builder self() {
            return this;
        }

        @Override
        public RecoveryCodeFactorOptions build() {
            Assert.hasText(super.processingUrl, "Processing URL must be set for Recovery Code factor.");
            return new RecoveryCodeFactorOptions(this);
        }
    }
}
