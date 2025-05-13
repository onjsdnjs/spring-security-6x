const TokenMemory = {
    storage: sessionStorage,

    useLocalStorage() {
        this.storage = localStorage;
    },

    useSessionStorage() {
        this.storage = sessionStorage;
    },

    get accessToken() {
        return this.storage.getItem("accessToken");
    },

    set accessToken(token) {
        this.storage.setItem("accessToken", token);
    },

    get refreshToken() {
        return this.storage.getItem("refreshToken");
    },

    set refreshToken(token) {
        this.storage.setItem("refreshToken", token);
    }
};