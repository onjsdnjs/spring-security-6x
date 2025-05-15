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
    const token = document.getElementById('tokenField').value;

    if (!username || !token) {
        console.error('OTT Forward: Username or token missing from hidden fields.');
        if (typeof showToast === 'function') showToast("자동 로그인 실패: 인증 정보가 올바르지 않습니다.", "error");
        else alert("자동 로그인 실패: 인증 정보가 올바르지 않습니다.");
        // 로그인 페이지로 리다이렉트 또는 오류 페이지 표시
        // window.location.href = '/loginForm';
        return;
    }

    const formData = new URLSearchParams();
    formData.append('username', username);
    formData.append('token', token);

    const headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    };
    if (csrfToken && csrfHeader) {
        headers[csrfHeader] = csrfToken;
    }

    try {
        console.log('Attempting OTT auto login with username:', username);
        const response = await fetch('/login/ott', { // 서버의 OTT 로그인 처리 URL
            method: 'POST',
            credentials: 'same-origin',
            headers: headers,
            body: formData.toString()
        });

        console.log('OTT Forward response status:', response.status, response.statusText);

        if (response.ok) {
            // 서버에서 성공 시 JWT 토큰 등을 반환할 수 있음.
            // 현재 TokenIssuingSuccessHandler가 이를 처리하고 토큰을 내려준다고 가정.
            // 또는 /login/ott 컨트롤러가 직접 SecurityContext에 인증 정보를 설정하고 리다이렉션할 수도 있음.
            // 여기서는 서버가 성공 시 홈으로 리다이렉션 하거나, 필요한 토큰 정보를 JSON으로 반환한다고 가정.

            // 만약 서버가 토큰을 반환하고 클라이언트가 저장해야 한다면:
            // const result = await response.json();
            // const authMode = localStorage.getItem("authMode") || "header";
            // if (authMode === "header" || authMode === "header_cookie") {
            //     TokenMemory.accessToken = result.accessToken;
            //     if (authMode === "header") {
            //         TokenMemory.refreshToken = result.refreshToken;
            //     }
            // }
            if (typeof showToast === 'function') showToast("OTT 로그인 성공!", "success", 1500);
            else alert("OTT 로그인 성공!");

            // 서버의 성공 핸들러가 리다이렉션을 처리할 것으로 예상.
            // 명시적으로 홈으로 보내려면:
            // setTimeout(() => { window.location.href = '/'; }, 500);
            // 현재 서버 구조상 /login/ott가 성공하면 SecurityContext가 채워지고,
            // 이후 /로의 접근은 인증된 사용자로 간주됨. 리다이렉트는 서버측에서 명시적으로 할 수도 있음.
            // 만약 서버가 JSON 응답만 한다면, 여기서 window.location.href = '/' 처리.
            // TokenIssuingSuccessHandler가 토큰을 응답 본문에 쓰고, 클라이언트가 리다이렉트 해야함.
            setTimeout(() => {
                // 서버 응답에 redirect URL이 있다면 그것을 따름
                // const data = await response.json();
                // window.location.href = data.redirectUrl || '/';
                window.location.href = '/'; // 기본적으로 홈으로
            }, 500);


        } else {
            const errorData = await response.json().catch(() => ({ message: 'OTT 자동 로그인에 실패했습니다.' }));
            console.error('OTT Forward login failed:', errorData);
            if (typeof showToast === 'function') showToast(`로그인 실패: ${errorData.message || response.statusText}`, "error");
            else alert(`로그인 실패: ${errorData.message || response.statusText}`);
            // 실패 시 로그인 페이지로 리다이렉트
            setTimeout(() => { window.location.href = '/loginOtt'; }, 2000);
        }
    } catch (error) {
        console.error('OTT Forward request error:', error);
        if (typeof showToast === 'function') showToast("로그인 요청 중 오류가 발생했습니다.", "error");
        else alert("로그인 요청 중 오류가 발생했습니다.");
        setTimeout(() => { window.location.href = '/loginOtt'; }, 2000);
    }
});