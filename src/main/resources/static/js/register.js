document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("registerForm");
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const data = {
            username: form.username.value,
            email: form.email.value,
            password: form.password.value
        };
        const res = await fetch(/*[[@{/api/auth/register}]]*/"/api/auth/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });
        if (res.ok) {
            alert("회원가입 성공!");
            window.location.href = /*[[@{/loginForm}]]*/"/loginForm";
        } else {
            alert("회원가입 실패");
        }
    });
});