package io.springsecurity.springsecurity6x.security.core.mfa.options.recovery;

import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class RecoveryCodeFactorOptions extends FactorAuthenticationOptions {
    // public RecoveryCodeStore getRecoveryCodeStore() { return recoveryCodeStore; }
    // public void setRecoveryCodeStore(RecoveryCodeStore recoveryCodeStore) { this.recoveryCodeStore = recoveryCodeStore; }
    // private RecoveryCodeStore recoveryCodeStore; // 복구 코드 저장/검증 서비스
    private int codeLength = 8; // 예시: 복구 코드 길이
    private int numberOfCodesToGenerate = 10; // 예시: 생성할 복구 코드 개수

    public RecoveryCodeFactorOptions() {
        super(AuthType.RECOVERY_CODE);
    }

}
