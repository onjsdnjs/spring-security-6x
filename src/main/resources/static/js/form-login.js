document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("loginForm");
    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        const data = {
            username: form.username.value,
            password: form.password.value
        };

        const csrfToken = getCookie('XSRF-TOKEN');

        try {
            const res = await fetch("/api/auth/login", {
                method:      "POST",
                credentials: "same-origin",           // 쿠키(인증, CSRF) 포함
                headers: {
                    "Content-Type": "application/json",
                    "X-XSRF-TOKEN": csrfToken
                },
                body: JSON.stringify(data)
            });

            if (res.ok) {
                // 로그인 성공 후 홈으로 이동
                window.location.href = "/";
            } else {
                const error = await res.json().catch(() => null);
                alert("로그인 실패: " + (error?.message || res.statusText));
            }
        } catch (err) {
            console.error("로그인 요청 중 오류:", err);
            alert("로그인 중 오류가 발생했습니다.");
        }
    });
});

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) {
        return parts.pop().split(';').shift();
    }
    return null;
}
