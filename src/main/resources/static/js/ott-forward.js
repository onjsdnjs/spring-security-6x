document.addEventListener('DOMContentLoaded', async () => {
    const form       = document.getElementById('forwardForm');
    const csrfToken  = document.querySelector('meta[name="_csrf"]').getAttribute('content');
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]').getAttribute('content');

    // 1) form 데이터 준비
    const formData = new URLSearchParams();
    formData.append('username', document.getElementById('usernameField').value);
    formData.append('token',    document.getElementById('tokenField').value);

    try {
        // 2) 자동 fetch 요청
        const res = await fetch('/login/ott', {
            method:      'POST',  // POST
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                [csrfHeader]:    csrfToken
            },
            body: formData.toString()
        });

        // 3) 응답 로그
        console.log('응답 객체:', res);
        console.log('응답 status:', res.status, res.statusText);

        // 4) 성공/실패 처리
        if (res.ok) {
            // 로그인 성공하면 홈으로
            window.location.href = '/';
        } else {
            const error = await res.json().catch(() => null);
            console.error('로그인 실패 응답 바디:', error);
            alert('로그인 실패: ' + (error?.message || res.statusText));
        }
    } catch (err) {
        console.error('OTT 로그인 요청 중 오류:', err);
        alert('로그인 요청에 실패했습니다.');
    }
});