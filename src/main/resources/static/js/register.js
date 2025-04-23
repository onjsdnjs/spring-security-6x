document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("registerForm");
    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        const data = {
            username: form.username.value,
            email:    form.email.value,
            password: form.password.value,
            roles:    form.roles.value,
        };

        const csrfToken = getCookie('XSRF-TOKEN');

        try {
            const res = await fetch("/api/register", {
                method:      "POST",
                credentials: "same-origin",     // 쿠키(인증·CSRF) 포함
                headers: {
                    "Content-Type": "application/json",
                    "X-XSRF-TOKEN": csrfToken
                },
                body: JSON.stringify(data)
            });

            if (res.ok) {
                alert("회원가입 성공!");
                window.location.href = "/loginForm";
            } else {
                const error = await res.json().catch(() => null);
                alert("회원가입 실패: " + (error?.message || res.statusText));
            }
        } catch (err) {
            console.error("회원가입 중 오류 발생:", err);
            alert("회원가입 중 오류가 발생했습니다.");
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