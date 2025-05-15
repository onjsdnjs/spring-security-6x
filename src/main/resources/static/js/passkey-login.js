document.addEventListener("DOMContentLoaded", () => {
    const passkeyButton = document.getElementById("passkeyBtn");
    const messageElement = document.getElementById("passkeyMessage"); // 메시지 표시용

    if (!passkeyButton) return;

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');

    function displayMessage(message, type = 'info') {
        if (messageElement) {
            messageElement.textContent = message;
            messageElement.className = `mt-4 text-sm ${type === 'error' ? 'text-red-600' : (type === 'success' ? 'text-green-600' : 'text-gray-500')}`;
        } else if (typeof showToast === 'function') {
            showToast(message, type);
        } else {
            alert(message);
        }
    }

    passkeyButton.addEventListener("click", async () => {
        displayMessage("Passkey 인증을 시작합니다...", "info");
        passkeyButton.disabled = true;

        const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
        const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

        if (!csrfToken || !csrfHeader) {
            displayMessage("오류: 보안 토큰을 찾을 수 없습니다. 페이지를 새로고침 해주세요.", "error");
            passkeyButton.disabled = false;
            return;
        }

        try {
            // 1. Assertion Options 요청
            const optionsResponse = await fetch("/webauthn/assertion/options", {
                method: "POST", // 서버 구현에 따라 GET 또는 POST (보안상 POST 권장, CSRF 필요)
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/json", // POST 요청 시 필요
                    [csrfHeader]: csrfToken
                }
                // username을 body로 보내야 할 수도 있음 (서버 구현 확인)
                // body: JSON.stringify({ username: "user_identifier_if_needed" })
            });

            if (!optionsResponse.ok) {
                const errorData = await optionsResponse.json().catch(() => ({message: "Passkey 옵션 요청 실패"}));
                throw new Error(`옵션 요청 실패: ${errorData.message || optionsResponse.statusText}`);
            }

            const publicKeyCredentialRequestOptions = await optionsResponse.json();
            console.log("Received PublicKeyCredentialRequestOptions:", publicKeyCredentialRequestOptions);

            // challenge가 base64url 인코딩된 문자열로 오면 ArrayBuffer로 변환 필요
            if (publicKeyCredentialRequestOptions.challenge) {
                publicKeyCredentialRequestOptions.challenge = base64UrlToArraryBuffer(publicKeyCredentialRequestOptions.challenge);
            }
            if (publicKeyCredentialRequestOptions.allowCredentials) {
                publicKeyCredentialRequestOptions.allowCredentials.forEach(cred => {
                    if (cred.id) {
                        cred.id = base64UrlToArraryBuffer(cred.id);
                    }
                });
            }


            // 2. navigator.credentials.get() 호출
            displayMessage("Passkey 장치로 인증을 확인해주세요...", "info");
            const assertion = await navigator.credentials.get({ publicKey: publicKeyCredentialRequestOptions });
            console.log("Received assertion from authenticator:", assertion);

            // 3. 서버로 Assertion 결과 전송
            displayMessage("인증 결과를 서버로 전송 중...", "info");

            // ArrayBuffer 들을 base64url 문자열로 변환하여 JSON 으로 전송
            const assertionResponse = {
                id: arrayBufferToBase64Url(assertion.rawId),
                rawId: arrayBufferToBase64Url(assertion.rawId),
                type: assertion.type,
                response: {
                    authenticatorData: arrayBufferToBase64Url(assertion.response.authenticatorData),
                    clientDataJSON: arrayBufferToBase64Url(assertion.response.clientDataJSON),
                    signature: arrayBufferToBase64Url(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? arrayBufferToBase64Url(assertion.response.userHandle) : null,
                },
            };


            const loginResponse = await fetch("/login/webauthn", {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/json",
                    [csrfHeader]: csrfToken
                },
                body: JSON.stringify(assertionResponse)
            });

            if (loginResponse.ok) {
                // 서버에서 로그인 성공 시 토큰 등을 반환할 수 있음.
                // 현재 프로젝트에서는 성공 시 페이지 리다이렉션 또는 SecurityContext에 인증 정보 저장.
                // init-auth.js가 토큰을 처리하거나, 서버가 쿠키를 설정할 것임.
                displayMessage("Passkey 인증 성공!", "success");
                // 서버 응답에 따라 토큰 저장 로직 추가 가능
                // const result = await loginResponse.json();
                // TokenMemory.accessToken = result.accessToken;
                // TokenMemory.refreshToken = result.refreshToken;
                setTimeout(() => {
                    window.location.href = "/"; // 성공 시 홈으로
                }, 1000);
            } else {
                const errorData = await loginResponse.json().catch(() => ({message: "Passkey 인증 실패"}));
                throw new Error(`인증 실패: ${errorData.message || loginResponse.statusText}`);
            }

        } catch (error) {
            console.error("Passkey login error:", error);
            displayMessage(`오류: ${error.message}`, "error");
            // navigator.credentials.get() 취소 시 AbortError 또는 NotAllowedError 발생 가능
            if (error.name === "NotAllowedError") {
                displayMessage("Passkey 인증이 사용자에 의해 취소되었거나, 허용되지 않은 작업입니다.", "info");
            } else if (error.name === "AbortError") {
                displayMessage("Passkey 인증 작업이 중단되었습니다.", "info");
            }
        } finally {
            passkeyButton.disabled = false;
        }
    });

    // Base64URL to ArrayBuffer
    function base64UrlToArraryBuffer(base64Url) {
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const raw = window.atob(base64);
        const buffer = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) {
            buffer[i] = raw.charCodeAt(i);
        }
        return buffer.buffer;
    }

    // ArrayBuffer to Base64URL
    function arrayBufferToBase64Url(buffer) {
        const bytes = new Uint8Array(buffer);
        let str = '';
        for (const charCode of bytes) {
            str += String.fromCharCode(charCode);
        }
        const base64 = window.btoa(str);
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
});