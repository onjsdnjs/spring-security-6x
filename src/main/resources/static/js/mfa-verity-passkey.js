document.addEventListener("DOMContentLoaded", () => {
    const passkeyVerifyButton = document.getElementById("mfaPasskeyVerifyBtn");
    const messageDiv = document.getElementById("mfaPasskeyVerifyMessage");

    if (!passkeyVerifyButton) return;

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

    const mfaSessionId = sessionStorage.getItem("mfaSessionId");
    const username = sessionStorage.getItem("mfaUsername");
    const currentFactor = sessionStorage.getItem("currentMfaFactor"); // "PASSKEY" 여야 함

    if (!mfaSessionId || !username || currentFactor !== "PASSKEY") {
        displayMessage("잘못된 접근입니다. MFA 세션을 다시 시작해주세요.", "error");
        if (typeof showToast === 'function') showToast("잘못된 접근입니다. MFA 세션을 확인해주세요.", "error", 3000);
        setTimeout(() => { window.location.href = "/loginForm"; }, 3000);
        return;
    }

    function displayMessage(message, type = 'info') { // 기본 info
        if (messageDiv) {
            messageDiv.textContent = message;
            messageDiv.className = `mt-4 text-sm text-center ${type === 'error' ? 'text-red-500' : (type === 'success' ? 'text-green-600' : 'text-gray-500')}`;
        } else if (typeof showToast === 'function') {
            showToast(message, type);
        } else {
            alert(message);
        }
    }

    passkeyVerifyButton.addEventListener("click", async () => {
        displayMessage("Passkey 인증을 시작합니다...", "info");
        passkeyVerifyButton.disabled = true;

        const headers = {
            "Content-Type": "application/json",
            "X-MFA-Session-Id": mfaSessionId,
            "X-Device-Id": getOrCreateDeviceId()
        };
        if (csrfToken && csrfHeader) headers[csrfHeader] = csrfToken;

        try {
            // 1. Passkey Assertion Options 요청 (MFA용)
            // 서버 API: `/api/mfa/assertion/options` (MfaApiController에 정의)
            const optionsResponse = await fetch(`/api/mfa/assertion/options`, {
                method: "POST",
                headers: headers, // MFA 세션 ID 포함
                body: JSON.stringify({ username: username }) // 서버에서 사용자 식별용
            });

            if (!optionsResponse.ok) {
                const errorData = await optionsResponse.json().catch(() => ({ message: "Passkey 옵션 요청 실패" }));
                throw new Error(`옵션 요청 실패: ${errorData.message || optionsResponse.statusText}`);
            }
            const publicKeyCredentialRequestOptions = await optionsResponse.json();
            // 서버에서 Base64URL 문자열로 온다면 변환. Spring Security WebAuthn API는 Map을 반환하므로 이미 객체일 수 있음.
            // 현재 MfaApiController의 /api/mfa/assertion/options는 WebAuthn 라이브러리를 직접 사용하지 않고,
            // 예시로 랜덤 challenge만 만들고 있어, 실제로는 Spring Security WebAuthn의 RelyingPartyAuthenticationRequest를 사용해야 함.
            // 여기서는 publicKeyCredentialRequestOptions가 이미 올바른 형식의 객체라고 가정.
            // challenge, allowCredentials.id 등은 ArrayBuffer로 변환 필요 (JS WebAuthn API 요구사항)
            if (publicKeyCredentialRequestOptions.challenge) {
                publicKeyCredentialRequestOptions.challenge = base64UrlToArraryBuffer(publicKeyCredentialRequestOptions.challenge);
            }
            if (publicKeyCredentialRequestOptions.allowCredentials) {
                publicKeyCredentialRequestOptions.allowCredentials.forEach(cred => {
                    if (cred.id) cred.id = base64UrlToArraryBuffer(cred.id);
                });
            }


            displayMessage("Passkey 장치(생체인증/보안키)로 인증을 확인해주세요...", "info");
            const assertion = await navigator.credentials.get({ publicKey: publicKeyCredentialRequestOptions });

            displayMessage("인증 결과를 서버로 전송 중...", "info");
            const assertionResponseForServer = {
                id: arrayBufferToBase64Url(assertion.rawId),
                rawId: arrayBufferToBase64Url(assertion.rawId),
                type: assertion.type,
                clientDataJSON: arrayBufferToBase64Url(assertion.response.clientDataJSON),
                authenticatorData: arrayBufferToBase64Url(assertion.response.authenticatorData),
                signature: arrayBufferToBase64Url(assertion.response.signature),
                userHandle: assertion.response.userHandle ? arrayBufferToBase64Url(assertion.response.userHandle) : null,
            };

            // 서버 API: MFA Passkey 검증 (Spring Security Filter가 처리하는 경로)
            // PlatformSecurityConfig에서 .mfa().passkey().loginProcessingUrl()에 설정된 값. 예: "/login/mfa-passkey"
            const loginResponse = await fetch(`/login/mfa-passkey`, {
                method: "POST",
                headers: { // Content-Type은 Spring Security WebAuthn 필터 스펙에 맞춰야 함 (보통 application/json)
                    "Content-Type": "application/json",
                    "X-MFA-Session-Id": mfaSessionId, // Filter에서 FactorContext 로드용
                    "X-Device-Id": getOrCreateDeviceId(),
                    ...( (csrfToken && csrfHeader) && { [csrfHeader]: csrfToken } )
                },
                body: JSON.stringify(assertionResponseForServer) // WebAuthn 필터가 이 구조를 기대
            });

            if (loginResponse.redirected && loginResponse.url.includes('/mfa/select-factor')) {
                const urlParams = new URLSearchParams(new URL(loginResponse.url).search);
                const errorMsg = urlParams.get('error_passkey_verify') || "Passkey 인증에 실패하여 다른 인증 수단을 선택합니다.";
                displayMessage(errorMsg, "error");
                showToast(errorMsg, "error");
                setTimeout(() => { window.location.href = loginResponse.url; }, 1500);
                return;
            }
            if (loginResponse.redirected && loginResponse.url.includes('/mfa/failure')) {
                const urlParams = new URLSearchParams(new URL(loginResponse.url).search);
                const errorMsg = urlParams.get('error_mfa_terminal') || "MFA 인증에 최종 실패했습니다.";
                displayMessage(errorMsg, "error");
                showToast(errorMsg, "error");
                setTimeout(() => { window.location.href = loginResponse.url; }, 1500);
                return;
            }


            const result = await loginResponse.json(); // MfaStepBasedSuccessHandler 또는 MfaCapableRestSuccessHandler가 JSON 반환 가정

            if (loginResponse.ok) {
                if (result.status === "MFA_COMPLETE") {
                    const authMode = localStorage.getItem("authMode") || "header";
                    if (authMode === "header" || authMode === "header_cookie") {
                        TokenMemory.accessToken = result.accessToken;
                        if (authMode === "header" && result.refreshToken) TokenMemory.refreshToken = result.refreshToken;
                    }
                    displayMessage("MFA 인증 성공!", "success");
                    showToast("MFA 인증 성공!", "success");
                    sessionStorage.removeItem("mfaSessionId");
                    sessionStorage.removeItem("mfaUsername");
                    sessionStorage.removeItem("currentMfaFactor");
                    setTimeout(() => { window.location.href = result.redirectUrl || "/"; }, 1000);
                } else if (result.status === "MFA_CONTINUE" && result.nextStepUrl) {
                    displayMessage("Passkey 인증 성공. 다음 MFA 단계로 이동합니다.", "info");
                    showToast("Passkey 인증 성공. 다음 MFA 단계로 이동합니다.", "info");
                    sessionStorage.setItem("currentMfaFactor", result.nextFactorType);
                    setTimeout(() => { window.location.href = result.nextStepUrl; }, 1000);
                } else {
                    throw new Error(result.message || "Passkey 인증 처리 중 알 수 없는 응답입니다.");
                }
            } else {
                const message = result.message || (loginResponse.status === 401 ? "Passkey 인증에 실패했습니다." : "Passkey 검증 실패");
                throw new Error(message);
            }

        } catch (error) {
            console.error("Error during MFA Passkey verification:", error);
            displayMessage(`오류: ${error.message}`, "error");
            if (error.name === "NotAllowedError") {
                displayMessage("Passkey 인증이 사용자에 의해 취소되었거나, 허용되지 않은 작업입니다.", "info");
            } else if (error.name === "AbortError" || error.name === "SecurityError") {
                displayMessage("Passkey 인증 작업이 중단되었거나 보안상의 이유로 실패했습니다.", "info");
            }
        } finally {
            passkeyVerifyButton.disabled = false;
        }
    });

    function getOrCreateDeviceId() {
        let deviceId = localStorage.getItem("deviceId");
        if (!deviceId) {
            deviceId = crypto.randomUUID();
            localStorage.setItem("deviceId", deviceId);
        }
        return deviceId;
    }
    function base64UrlToArraryBuffer(base64Url) {
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const raw = window.atob(base64);
        const buffer = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) { buffer[i] = raw.charCodeAt(i); }
        return buffer.buffer;
    }
    function arrayBufferToBase64Url(buffer) {
        const bytes = new Uint8Array(buffer);
        let str = '';
        for (const charCode of bytes) { str += String.fromCharCode(charCode); }
        const base64 = window.btoa(str);
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
});