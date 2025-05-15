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
    const currentFactor = sessionStorage.getItem("currentMfaFactor");

    if (!mfaSessionId || currentFactor !== "PASSKEY") {
        displayMessage("잘못된 접근입니다. MFA 세션을 다시 시작해주세요.", "error");
        if (typeof showToast === 'function') showToast("잘못된 접근입니다.", "error", 3000);
        setTimeout(() => { window.location.href = "/loginForm"; }, 3000);
        return;
    }

    function displayMessage(message, type = 'info') {
        if (messageDiv) {
            messageDiv.textContent = message;
            messageDiv.className = `mt-4 text-sm text-center ${type === 'error' ? 'text-red-600' : (type === 'success' ? 'text-green-600' : 'text-gray-500')}`;
        } else if (typeof showToast === 'function') {
            showToast(message, type);
        } else {
            alert(message);
        }
    }

    passkeyVerifyButton.addEventListener("click", async () => {
        displayMessage("Passkey 인증을 시작합니다...", "info");
        passkeyVerifyButton.disabled = true;

        const headers = { "Content-Type": "application/json" };
        if (csrfToken && csrfHeader) headers[csrfHeader] = csrfToken;
        headers["X-MFA-Session-Id"] = mfaSessionId;
        headers["X-Device-Id"] = getOrCreateDeviceId();

        try {
            // 1. Passkey Assertion Options 요청 (MFA용)
            // 서버 API: `/api/mfa/challenge` (POST, factorType=PASSKEY, event=REQUEST_CHALLENGE)
            const optionsResponse = await fetch(`/api/mfa/challenge`, {
                method: "POST",
                headers: headers,
                body: JSON.stringify({ factorType: "PASSKEY", username: username, event: "REQUEST_CHALLENGE" })
            });

            if (!optionsResponse.ok) {
                const errorData = await optionsResponse.json().catch(() => ({ message: "Passkey 옵션 요청 실패" }));
                throw new Error(`옵션 요청 실패: ${errorData.message || optionsResponse.statusText}`);
            }
            const publicKeyCredentialRequestOptions = await optionsResponse.json();

            if (publicKeyCredentialRequestOptions.challenge) {
                publicKeyCredentialRequestOptions.challenge = base64UrlToArraryBuffer(publicKeyCredentialRequestOptions.challenge);
            }
            if (publicKeyCredentialRequestOptions.allowCredentials) {
                publicKeyCredentialRequestOptions.allowCredentials.forEach(cred => {
                    if (cred.id) cred.id = base64UrlToArraryBuffer(cred.id);
                });
            }

            // 2. navigator.credentials.get() 호출
            displayMessage("Passkey 장치(생체인증/보안키)로 인증을 확인해주세요...", "info");
            const assertion = await navigator.credentials.get({ publicKey: publicKeyCredentialRequestOptions });

            // 3. 서버로 Assertion 결과 전송 (MFA용)
            displayMessage("인증 결과를 서버로 전송 중...", "info");
            const assertionResponseForServer = {
                id: arrayBufferToBase64Url(assertion.rawId),
                rawId: arrayBufferToBase64Url(assertion.rawId),
                type: assertion.type,
                response: {
                    authenticatorData: arrayBufferToBase64Url(assertion.response.authenticatorData),
                    clientDataJSON: arrayBufferToBase64Url(assertion.response.clientDataJSON),
                    signature: arrayBufferToBase64Url(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? arrayBufferToBase64Url(assertion.response.userHandle) : null,
                }
            };
            // 서버 API: `/api/mfa/verify` (POST, factorType=PASSKEY, event=SUBMIT_CREDENTIAL)
            const loginResponse = await fetch(`/api/mfa/verify`, {
                method: "POST",
                headers: headers, // MFA 세션 ID 포함된 헤더 재사용
                body: JSON.stringify({ factorType: "PASSKEY", webauthnResponse: assertionResponseForServer, event: "SUBMIT_CREDENTIAL" })
            });

            const result = await loginResponse.json();
            if (loginResponse.ok) {
                if (result.status === "MFA_COMPLETE") { // 최종 성공
                    const authMode = localStorage.getItem("authMode") || "header";
                    if (authMode === "header" || authMode === "header_cookie") {
                        TokenMemory.accessToken = result.accessToken;
                        if (authMode === "header") TokenMemory.refreshToken = result.refreshToken;
                    }
                    displayMessage("MFA 인증 성공!", "success");
                    sessionStorage.removeItem("mfaSessionId");
                    sessionStorage.removeItem("mfaUsername");
                    sessionStorage.removeItem("currentMfaFactor");
                    setTimeout(() => { window.location.href = result.redirectUrl || "/"; }, 1000);
                } else if (result.status === "MFA_CONTINUE" && result.nextStepUrl) { // 다른 MFA 단계
                    displayMessage("Passkey 인증 성공. 다음 단계로 이동합니다.", "info");
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
            // 실패 시 다른 인증 수단 선택 페이지로 이동하는 버튼 활성화 고려
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

    // 페이지 로드 시 바로 Passkey 인증 시도 (Conditional UI를 사용하지 않는 경우)
    // passkeyVerifyButton.click();
});