document.getElementById("passkeyBtn").addEventListener("click", async () => {
    try {
        const options = await fetch("/webauthn/assertion/options").then(r => r.json());
        const assertion = await navigator.credentials.get({ publicKey: options });
        const res = await fetch("/login/passkey", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(assertion)
        });
        if (res.ok) {
            window.location.href = "/users";
        } else {
            alert("Passkey 인증에 실패했습니다.");
        }
    } catch {
        alert("Passkey 인증 중 오류가 발생했거나 지원되지 않는 브라우저입니다.");
    }
});