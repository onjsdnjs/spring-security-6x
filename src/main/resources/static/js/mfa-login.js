// File: /js/mfa-login.js

document.addEventListener("DOMContentLoaded", () => {
    const steps = [
        document.getElementById("restForm"),
        document.getElementById("ottForm"),
        document.getElementById("passkeySection")
    ];
    let current = 0;

    // 공통 CSRF·DeviceId 준비
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]')?.content;
    const csrfToken  = document.querySelector('meta[name="_csrf"]')?.content;
    const deviceId   = getOrCreateDeviceId();
    const authMode   = localStorage.getItem("authMode") || "cookie";

    function makeHeaders() {
        const h = {
            "Content-Type": "application/json",
            "X-Device-Id": deviceId
        };
        if (authMode !== "header" && csrfHeader && csrfToken) {
            h[csrfHeader] = csrfToken;
        }
        return h;
    }

    function showStep(idx) {
        steps.forEach((el,i) => el.style.display = (i===idx ? "" : "none"));
        current = idx;
    }

    function handleTokens(result) {
        if (authMode === "header") {
            TokenMemory.accessToken  = result.accessToken;
            TokenMemory.refreshToken = result.refreshToken;
        } else if (authMode === "header_cookie") {
            TokenMemory.accessToken = result.accessToken;
        }
    }

    // 1단계: REST 로그인
    const restForm = steps[0];
    restForm.addEventListener("submit", async e => {
        e.preventDefault();
        const payload = {
            user: restForm.username.value,
            pass: restForm.password.value
        };
        try {
            const res = await fetch("/api/auth/login", {
                method: "POST",
                credentials: "same-origin",
                headers: makeHeaders(),
                body: JSON.stringify(payload)
            });
            if (!res.ok) throw await res.json();
            // 다음 OTP 단계 이동
            showStep(1);
        } catch (err) {
            alert("로그인 실패: " + (err?.message || err));
        }
    });

    // 2단계: OTT(이메일 코드) 인증
    const ottForm = steps[1];
    ottForm.addEventListener("submit", async e => {
        e.preventDefault();
        const payload = { token: ottForm.token.value };
        try {
            const res = await fetch("/ott/generate", {
                method:      "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    [csrfHeader]:    csrfToken
                },
                body: new URLSearchParams({ username: email }) // 'username' 키로 전달
            });
            if (res.ok) {
                // 성공 시 발송 완료 페이지로 이동
                window.location.href = `/ott/sent?email=${encodeURIComponent(email)}`;
            } else {
                throw new Error();
            }
            // 다음 Passkey 단계 이동
            showStep(2);
        } catch (err) {
            alert("코드 인증 실패: " + (err?.message || err));
        }
    });

    // 3단계: Passkey 인증
    const passkeyBtn = document.getElementById("webauthnBtn");
    passkeyBtn.addEventListener("click", async e => {
        e.preventDefault();
        try {
            // 3-1) WebAuthn 옵션 요청
            const optRes = await fetch("/api/auth/mfa/options", {
                method: "POST",
                credentials: "same-origin",
                headers: makeHeaders()
            });
            if (!optRes.ok) throw new Error("Passkey 옵션 요청 실패");
            const publicKey = await optRes.json();

            // 3-2) 브라우저 API
            const cred = await navigator.credentials.get({ publicKey });
            const authData = {
                credentialId:      arrayBufToB64(cred.rawId),
                clientDataJSON:    arrayBufToB64(cred.response.clientDataJSON),
                authenticatorData: arrayBufToB64(cred.response.authenticatorData),
                signature:         arrayBufToB64(cred.response.signature),
                userHandle:        arrayBufToB64(cred.response.userHandle)
            };

            // 3-3) 최종 MFA 완료 호출
            const res = await fetch("/api/auth/mfa?event=ISSUE_TOKEN", {
                method: "POST",
                credentials: "same-origin",
                headers: makeHeaders(),
                body: JSON.stringify({ webauthnResponse: authData })
            });
            if (!res.ok) throw await res.json();
            const result = await res.json();
            handleTokens(result);
            window.location.href = "/";
        } catch (err) {
            alert("Passkey 인증 실패: " + (err.message || err));
        }
    });

    // Helpers
    function getOrCreateDeviceId() {
        let id = localStorage.getItem("deviceId");
        if (!id) {
            id = crypto.randomUUID();
            localStorage.setItem("deviceId", id);
        }
        return id;
    }
    function arrayBufToB64(buf) {
        const bytes = new Uint8Array(buf), len = bytes.byteLength;
        let str = "";
        for (let i=0; i<len; i++) str += String.fromCharCode(bytes[i]);
        return btoa(str);
    }

    // 초기 화면
    showStep(0);
});
