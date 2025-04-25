document.addEventListener('DOMContentLoaded', function() {
    const form      = document.getElementById('forwardForm');
    const csrfToken = document.querySelector('meta[name="_csrf"]').getAttribute('content');
    const csrfHeader= document.querySelector('meta[name="_csrf_header"]').getAttribute('content');

    if (!form) return;

    // 폼 데이터 수집
    const formData = new URLSearchParams();
    formData.append('username', form.username.value);
    formData.append('token', form.token.value);

    // AJAX 요청
    fetch(form.getAttribute('action'), {
        method:      form.getAttribute('method').toUpperCase(),
        credentials: 'same-origin',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            [csrfHeader]: csrfToken
        },
        body: formData
    })
        .then(async res => {
            if (res.ok) {
                // 로그인 성공 시 루트 페이지로 이동
                window.location.href = '/';
            } else {
                // 실패 시 에러 메시지 표시
                const error = await res.json().catch(() => null);
                alert('로그인 실패: ' + (error?.message || res.statusText));
            }
        })
        .catch(err => {
            console.error('OTT 로그인 요청 중 오류:', err);
            alert('로그인 요청에 실패했습니다.');
        });
});
