document.addEventListener('DOMContentLoaded', async () => {
    const forwardForm = document.getElementById('forwardForm');
    if (!forwardForm) {
        console.error('OTT Forward Form not found!');
        if (typeof showToast === 'function') showToast("자동 로그인 오류: 필수 정보 누락.", "error");
        else alert("자동 로그인 오류: 필수 정보 누락.");
        return;
    }

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

    const username = document.getElementById('usernameField').value;
    const token = document.getElementById('tokenField').value; // This is the one-time token from the magic link

    if (!username || !token) {
        console.error('OTT Forward: Username or token missing from hidden fields.');
        if (typeof showToast === 'function') showToast("자동 로그인 실패: 인증 정보가 올바르지 않습니다.", "error");
        else alert("자동 로그인 실패: 인증 정보가 올바르지 않습니다.");
        setTimeout(() => { window.location.href = '/loginOtt'; }, 2000);
        return;
    }

    const formData = new URLSearchParams();
    formData.append('username', username);
    formData.append('token', token); // Spring Security의 OneTimeTokenAuthenticationFilter는 이 파라미터를 사용

    const headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        "X-Device-Id": getOrCreateDeviceId() // Device ID 추가
    };
    if (csrfToken && csrfHeader) {
        headers[csrfHeader] = csrfToken;
    }

    try {
        console.log('Attempting OTT auto login with username:', username);
        // 대상 URL은 Spring Security 설정에서 oneTimeTokenLogin().loginProcessingUrl()에 지정된 경로
        const response = await fetch('/login/ott', {
            method: 'POST',
            credentials: 'same-origin',
            headers: headers,
            body: formData.toString()
        });

        console.log('OTT Forward response status:', response.status, response.statusText);
        const result = await response.json().catch(() => null); // 모든 응답을 JSON으로 파싱 시도

        if (response.ok && result) {
            if (result.status === "MFA_REQUIRED") {
                sessionStorage.setItem("mfaSessionId", result.mfaSessionId);
                sessionStorage.setItem("mfaUsername", username);
                showToast("OTT 인증 성공. 2차 인증이 필요합니다.", "info", 2000);
                setTimeout(() => {
                    window.location.href = result.nextStepUrl || "/mfa/select-factor";
                }, 1500);
                return;
            }

            // MFA가 필요 없는 일반 성공 또는 MFA 최종 완료 후
            const authMode = localStorage.getItem("authMode") || "header";
            if (authMode === "header" || authMode === "header_cookie") {
                if(result.accessToken) TokenMemory.accessToken = result.accessToken;
                if (authMode === "header" && result.refreshToken) {
                    TokenMemory.refreshToken = result.refreshToken;
                }
            }
            showToast("OTT 로그인 성공!", "success", 1500);
            setTimeout(() => {
                window.location.href = result.redirectUrl || '/';
            }, 500);

        } else {
            const errorMessage = result?.message || (response.status === 401 ? 'OTT 인증에 실패했습니다.' : '알 수 없는 오류가 발생했습니다.');
            console.error('OTT Forward login failed:', result || response.statusText);
            if (typeof showToast === 'function') showToast(`로그인 실패: ${errorMessage}`, "error");
            else alert(`로그인 실패: ${errorMessage}`);
            setTimeout(() => { window.location.href = '/loginOtt'; }, 2000);
        }
    } catch (error) {
        console.error('OTT Forward request error:', error);
        if (typeof showToast === 'function') showToast("로그인 요청 중 오류가 발생했습니다.", "error");
        else alert("로그인 요청 중 오류가 발생했습니다.");
        setTimeout(() => { window.location.href = '/loginOtt'; }, 2000);
    }

    function getOrCreateDeviceId() {
        let deviceId = localStorage.getItem("deviceId");
        if (!deviceId) {
            deviceId = crypto.randomUUID();
            localStorage.setItem("deviceId", deviceId);
        }
        return deviceId;
    }
});