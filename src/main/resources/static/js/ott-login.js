document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("ottForm");
    const msg  = document.getElementById("message");
    const csrfToken  = document.querySelector('meta[name="_csrf"]').content;
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]').content;

    form.addEventListener("submit", async e => {
        e.preventDefault();
        const email = document.getElementById("email").value;
        try {
            const res = await fetch("/ott/generate", {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    [csrfHeader]: csrfToken
                },
                body: new URLSearchParams({ email })
            });
            if (res.ok) {
                window.location.href = `/ott/sent?email=${encodeURIComponent(email)}&token=${token}`;
            } else {
                throw new Error();
            }
        } catch {
            msg.innerText = "토큰 요청에 실패했습니다.";
            msg.style.display = "block";
        }
    });
});
