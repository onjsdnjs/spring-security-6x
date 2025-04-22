document.getElementById("passkeyLoginBtn").addEventListener("click", async function () {
    try {
        const response = await fetch("/passkey/login-initiate");
        const options = await response.json();
        const assertion = await navigator.credentials.get({ publicKey: options });

        const result = await fetch("/passkey/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(assertion)
        });

        if (result.ok) {
            window.location.href = "/users";
        } else {
            alert("Passkey verification failed");
        }
    } catch (err) {
        console.error("Passkey error:", err);
    }
});
