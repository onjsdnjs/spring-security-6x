document.addEventListener("DOMContentLoaded", () => {
    const restForm = document.getElementById("restForm");
    const ottForm = document.getElementById("ottForm");
    const passkeySection = document.getElementById("passkeySection");
    const mfaStepIndicator = document.getElementById("mfaStepIndicator");

    // 각 폼/섹션의 메시지 영역
    const restFormMessage = document.getElementById("restFormMessage");
    const ottFormMessage = document.getElementById("ottFormMessage");
    const mfaOttEmailDisplay = document.getElementById("mfaOttEmail");
    const passkeySectionMessage = document.getElementById("passkeySectionMessage");
    const resendOttCodeButton = document.getElementById("resendOttCode");


    if (!restForm || !ottForm || !passkeySection) {
        console.error("MFA L_LOGIN: One or more MFA step elements not found.");
        return;
    }

    const steps = [restForm, ottForm, passkeySection];
    let currentStepIndex = 0;
    let mfaSessionData = { // MFA 흐름 동안 유지될 데이터 (예: mfaSessionId, username)
        mfaSessionId: null,
        username: null,
        deviceId: getOrCreateDeviceId()
    };


    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;
    const authMode = localStorage.getItem("authMode") || "header";

    function displayStepMessage(stepIndex, message, type = 'error') {
        let targetElement;
        if (stepIndex === 0) targetElement = restFormMessage;
        else if (stepIndex === 1) targetElement = ottFormMessage;
        else if (stepIndex === 2) targetElement = passkeySectionMessage;

        if (targetElement) {
            targetElement.textContent = message;
            targetElement.className = `text-sm text-center ${type === 'error' ? 'text-red-600' : 'text-green-600'}`;
        } else if (typeof showToast === 'function') {
            showToast(message, type);
        } else {
            alert(message);
        }
    }

    function updateStepIndicator(stepName) {
        if (mfaStepIndicator) {
            mfaStepIndicator.textContent = stepName;
        }
    }


    function showStep(index) {
        steps.forEach((step, i) => {
            step.style.display = i === index ? "" : "none";
        });
        currentStepIndex = index;
        // 각 단계에 맞는 인디케이터 업데이트
        if (index === 0) updateStepIndicator("1단계: 계정 정보 입력");
        else if (index === 1) updateStepIndicator("2단계: 이메일 코드 인증");
        else if (index === 2) updateStepIndicator("3단계: Passkey 인증");
    }

    function getOrCreateDeviceId() {
        let deviceId = localStorage.getItem("deviceId");
        if (!deviceId) {
            deviceId = crypto.randomUUID();
            localStorage.setItem("deviceId", deviceId);
        }
        return deviceId;
    }

    function createHeaders(includeContentType = true) {
        const headers = {};
        if (includeContentType) {
            headers["Content-Type"] = "application/json";
        }
        if (authMode !== "header" && csrfToken && csrfHeader) {
            headers[csrfHeader] = csrfToken;
        }
        // 헤더 기반 토큰 인증 모드일 경우, 필요시 AccessToken 추가 (MFA 중간 단계에서는 보통 불필요)
        // if (authMode === "header" || authMode === "header_cookie") {
        //     const accessToken = TokenMemory.accessToken;
        //     if (accessToken) headers["Authorization"] = `Bearer ${accessToken}`;
        // }
        // MFA 세션 ID는 요청 본문이나 URL 파라미터로 전달하는 것이 일반적일 수 있음
        // 또는 X-MFA-Session 헤더 등으로 전달 (서버 스펙 확인)
        if (mfaSessionData.mfaSessionId) {
            headers["X-MFA-Session-Id"] = mfaSessionData.mfaSessionId;
        }
        headers["X-Device-Id"] = mfaSessionData.deviceId;
        return headers;
    }


    // --- 1단계: 기본 로그인 (ID/PW) ---
    restForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const username = restForm.username.value;
        const password = restForm.password.value;
        mfaSessionData.username = username; // MFA 흐름에서 사용할 사용자 이름 저장

        displayStepMessage(0, "인증 중...", "info");

        try {
            // `/api/auth/login`은 MFA 필요 여부를 판단하고, 필요시 MFA 세션 시작 정보를 반환해야 함
            const response = await fetch("/api/auth/login", {
                method: "POST",
                headers: createHeaders(),
                body: JSON.stringify({ username, password })
            });

            const result = await response.json();

            if (response.ok && result.status === "MFA_REQUIRED") {
                mfaSessionData.mfaSessionId = result.mfaSessionId; // 서버에서 생성된 MFA 세션 ID 저장
                if (mfaOttEmailDisplay) mfaOttEmailDisplay.textContent = username; // OTT 폼에 이메일 표시

                // 서버 응답에 따라 다음 단계로 이동
                // 예: result.nextFactorType === 'OTT' 이면 OTT 폼으로
                // 여기서는 고정적으로 OTT 폼으로 이동한다고 가정
                displayStepMessage(0, "1차 인증 성공. 2차 인증으로 이동합니다.", "success");
                // 2차 인증(OTT) 챌린지 자동 요청
                await requestOttChallenge(); // OTT 코드 발송 요청
                showStep(1); // OTT 폼으로 이동
            } else if (response.ok) { // MFA_REQUIRED가 아닌 일반 성공 (MFA 불필요)
                if (authMode === "header" || authMode === "header_cookie") {
                    TokenMemory.accessToken = result.accessToken;
                    if (authMode === "header") TokenMemory.refreshToken = result.refreshToken;
                }
                if (typeof showToast === 'function') showToast("로그인 성공!", "success"); else alert("로그인 성공!");
                window.location.href = result.redirect || "/";
            }
            else {
                displayStepMessage(0, `1차 인증 실패: ${result.message || response.statusText}`, "error");
            }
        } catch (error) {
            console.error("MFA L_LOGIN - Step 1 (REST) error:", error);
            displayStepMessage(0, "1차 인증 요청 중 오류 발생", "error");
        }
    });

    async function requestOttChallenge() {
        if (!mfaSessionData.username) {
            displayStepMessage(1, "OTT 코드 요청 실패: 사용자 정보 없음", "error");
            return false;
        }
        displayStepMessage(1, "OTT 인증 코드를 요청 중입니다...", "info");
        try {
            // 서버 API: MFA OTT 챌린지 요청 (예: `/api/mfa/challenge?factor=ott`)
            // 요청 본문에는 mfaSessionId 또는 username 이 포함될 수 있음 (서버 스펙에 따라)
            const response = await fetch(`/api/mfa/challenge?event=REQUEST_CHALLENGE&factorType=OTT`, { // 서버 엔드포인트 확인 필요
                method: "POST",
                headers: createHeaders(),
                body: JSON.stringify({ username: mfaSessionData.username /*, mfaSessionId: mfaSessionData.mfaSessionId */ })
            });

            if (response.ok) {
                const challengeResult = await response.json();
                console.log("OTT Challenge requested successfully:", challengeResult);
                displayStepMessage(1, `이메일(${mfaSessionData.username})로 인증 코드가 발송되었습니다.`, "success");
                return true;
            } else {
                const errorData = await response.json().catch(() => ({message: "OTT 코드 요청 실패"}));
                displayStepMessage(1, `OTT 코드 요청 실패: ${errorData.message || response.statusText}`, "error");
                return false;
            }
        } catch (error) {
            console.error("MFA L_LOGIN - Request OTT Challenge error:", error);
            displayStepMessage(1, "OTT 코드 요청 중 오류 발생", "error");
            return false;
        }
    }

    if(resendOttCodeButton) {
        resendOttCodeButton.addEventListener("click", async () => {
            resendOttCodeButton.disabled = true;
            await requestOttChallenge();
            setTimeout(() => { resendOttCodeButton.disabled = false; }, 30000); // 30초 후 재전송 가능
        });
    }


    // --- 2단계: OTT 코드 인증 ---
    ottForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const ottCode = ottForm.token.value;
        displayStepMessage(1, "OTT 코드 인증 중...", "info");

        try {
            // 서버 API: MFA OTT 코드 검증 (예: `/api/mfa/verify?factor=ott`)
            // 요청 본문에는 mfaSessionId와 사용자가 입력한 ottCode가 포함되어야 함
            const response = await fetch(`/api/mfa/verify?event=SUBMIT_CREDENTIAL&factorType=OTT`, { // 서버 엔드포인트 확인 필요
                method: "POST",
                headers: createHeaders(),
                body: JSON.stringify({ token: ottCode /*, mfaSessionId: mfaSessionData.mfaSessionId */ })
            });

            const result = await response.json();

            if (response.ok && result.status === "MFA_CONTINUE") { // OTT 검증 성공, 다음 MFA 단계로
                displayStepMessage(1, "OTT 코드 인증 성공. 다음 단계로 이동합니다.", "success");
                // 서버 응답에 따라 다음 Factor가 Passkey 인지 확인 후 Passkey 단계로 이동
                // if (result.nextFactorType === 'PASSKEY') { ... }
                showStep(2); // Passkey 인증 단계로 이동
            } else if (response.ok && result.status === "MFA_COMPLETE") { // 모든 MFA 완료, 토큰 발급
                if (authMode === "header" || authMode === "header_cookie") {
                    TokenMemory.accessToken = result.accessToken;
                    if (authMode === "header") TokenMemory.refreshToken = result.refreshToken;
                }
                if (typeof showToast === 'function') showToast("MFA 로그인 성공!", "success"); else alert("MFA 로그인 성공!");
                window.location.href = result.redirect || "/";
            }
            else {
                displayStepMessage(1, `OTT 코드 인증 실패: ${result.message || response.statusText}`, "error");
            }
        } catch (error) {
            console.error("MFA L_LOGIN - Step 2 (OTT) error:", error);
            displayStepMessage(1, "OTT 코드 인증 요청 중 오류 발생", "error");
        }
    });


    // --- 3단계: Passkey 인증 ---
    const passkeyButton = document.getElementById("webauthnBtn");
    if (passkeyButton) {
        passkeyButton.addEventListener("click", async () => {
            displayStepMessage(2, "Passkey 인증을 준비 중입니다...", "info");
            passkeyButton.disabled = true;

            try {
                // 1. Passkey Assertion Options 요청 (MFA용)
                // 서버 API: MFA Passkey 옵션 요청 (예: `/api/mfa/challenge?factor=passkey`)
                const optionsResponse = await fetch(`/api/mfa/challenge?event=REQUEST_CHALLENGE&factorType=PASSKEY`, { // 서버 엔드포인트 확인 필요
                    method: "POST", // POST 권장
                    headers: createHeaders(),
                    body: JSON.stringify({ username: mfaSessionData.username /*, mfaSessionId: mfaSessionData.mfaSessionId */ })
                });

                if (!optionsResponse.ok) {
                    const errorData = await optionsResponse.json().catch(() => ({message: "Passkey 옵션 요청 실패"}));
                    throw new Error(`옵션 요청 실패: ${errorData.message || optionsResponse.statusText}`);
                }
                const publicKeyCredentialRequestOptions = await optionsResponse.json();
                console.log("MFA - Received PublicKeyCredentialRequestOptions:", publicKeyCredentialRequestOptions);

                // challenge 및 allowCredentials.id 를 ArrayBuffer로 변환
                if (publicKeyCredentialRequestOptions.challenge) {
                    publicKeyCredentialRequestOptions.challenge = base64UrlToArraryBuffer(publicKeyCredentialRequestOptions.challenge);
                }
                if (publicKeyCredentialRequestOptions.allowCredentials) {
                    publicKeyCredentialRequestOptions.allowCredentials.forEach(cred => {
                        if (cred.id) cred.id = base64UrlToArraryBuffer(cred.id);
                    });
                }

                // 2. navigator.credentials.get() 호출
                displayStepMessage(2, "Passkey 장치로 인증을 확인해주세요...", "info");
                const assertion = await navigator.credentials.get({ publicKey: publicKeyCredentialRequestOptions });

                // 3. 서버로 Assertion 결과 전송 (MFA용)
                // 서버 API: MFA Passkey 검증 (예: `/api/mfa/verify?factor=passkey&event=ISSUE_TOKEN`)
                // event=ISSUE_TOKEN 은 마지막 단계에서 토큰 발급을 의미할 수 있음 (서버 설계에 따름)
                displayStepMessage(2, "Passkey 인증 결과를 서버로 전송 중...", "info");
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

                const loginResponse = await fetch(`/api/mfa/verify?event=SUBMIT_CREDENTIAL&factorType=PASSKEY`, { // 서버 엔드포인트 확인 필요
                    method: "POST",
                    headers: createHeaders(),
                    body: JSON.stringify({ webauthnResponse: assertionResponseForServer /*, mfaSessionId: mfaSessionData.mfaSessionId */ })
                });

                const result = await loginResponse.json();
                if (loginResponse.ok && result.status === "MFA_COMPLETE") { // MFA 최종 성공
                    if (authMode === "header" || authMode === "header_cookie") {
                        TokenMemory.accessToken = result.accessToken;
                        if (authMode === "header") TokenMemory.refreshToken = result.refreshToken;
                    }
                    displayStepMessage(2, "MFA 로그인 성공!", "success");
                    setTimeout(() => { window.location.href = result.redirect || "/"; }, 1000);
                } else {
                    throw new Error(`Passkey 인증 실패: ${result.message || loginResponse.statusText}`);
                }

            } catch (error) {
                console.error("MFA L_LOGIN - Step 3 (Passkey) error:", error);
                displayStepMessage(2, `Passkey 인증 오류: ${error.message}`, "error");
                if (error.name === "NotAllowedError") {
                    displayStepMessage(2, "Passkey 인증이 사용자에 의해 취소되었거나, 허용되지 않은 작업입니다.", "info");
                }
            } finally {
                passkeyButton.disabled = false;
            }
        });
    }

    // Base64URL <-> ArrayBuffer 변환 함수 (passkey-login.js와 동일)
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

    // 초기 화면 설정
    showStep(0);
});