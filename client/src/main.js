const SERVER_URL = '127.0.0.1'
const PORT = 8000

const AUTH_URL = `http://${SERVER_URL}:${PORT}/auth`

class Auth {
    static async authenticate() {
        await this.request('RequestUniqueKey')
            .then(res => {
                // Receive serverUniqueKey
                if (res.uniqueKey && this.isValidKey(res.uniqueKey)) {
                    this.serverUniqueKey = res.uniqueKey
                    return true
                }
            })
            .then(() => {
                // Send privateKey
                this.privateKey = this.generatePrivateKey()
                return this.request('SendPrivateKey', {
                    encode: 'uniqueKey',
                    privateKey: this.encode(this.privateKey, this.serverUniqueKey)
                })
            })
            .then(res => {
                if (res.success && res.accessToken) {
                    this.accessToken = res.accessToken
                    console.log(this.accessToken)
                } else {
                    console.log(res)
                }
            })

    }

    static async request(reqName, params) {
        return await fetch(`${AUTH_URL}`, {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ request: reqName, ...params })
            })
            .then(data => data.json())
    }

    static encode(text, key) {
        return text + ' encoded with ' + key
    }

    static isValidKey(key) {
        return true
    }

    static generatePrivateKey() {
        return 'aenor12345'
    }

}