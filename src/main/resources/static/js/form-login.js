document.addEventListener("DOMContentLoaded", () => {
    // 로그인 후 토큰 저장 예시
    const form = document.getElementById("loginForm");
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const data = {
            email: form.email.value,
            password: form.password.value
        };
        const res = await fetch(/*[[@{/api/auth/login}]]*/"/api/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });
        if (res.ok) {
            const { accessToken } = await res.json();
            localStorage.setItem("accessToken", accessToken);
            window.location.href = /*[[@{/users}]]*/"/users";
        } else {
            alert("로그인 실패");
        }
    });
});