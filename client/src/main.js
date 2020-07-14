const SERVER_URL = '127.0.0.1'
const PORT = 8081

const AUTH_URL = `http://${SERVER_URL}:${PORT}/auth`

// TODO:
//  - Better library style API :
//      - Getter & setter
//      - jsdoc ?

class Auth {
    static async authenticate() {
        await this.request('RequestUniqueKey')
            .then(res => {
                // Receive serverUniqueKey
                if (res.uniqueKey && this.isValidKey(res.uniqueKey)) {
                    this.serverUniqueKey = res.uniqueKey
                    console.log('Receive valid uniqueKey :', this.serverUniqueKey)
                    return true
                } else {
                    console.log('Error with unique key')
                }
            })
            .then(() => {
                // Send privateKey
                this.privateKey = Auth.generatePrivateKey()
                return this.request('SendPrivateKey', {
                    encode: 'true',
                    privateKey: this.encode(this.privateKey, this.serverUniqueKey)
                })
            })
            .then(res => {
                if (res.success && res.accessToken) {
                    this.isAuthentified = true
                    this.accessToken = this.decode(res.accessToken, this.privateKey)
                    this.accessTokenInfo = JSON.parse(this.decode(this.accessToken, this.privateKey))
                    Auth.bindEvents()
                    console.log(this.accessToken, this.accessTokenInfo)
                } else {
                    console.log(res)
                }
            })
    }

    static async disconnect() {
        this.request('Disconnect')
            .then(res => {
                if (res.disconnected) {
                    console.log('Disconnection successfull')
                } else {
                    console.log('Ann error has occured')
                }
            })
            .catch(err => console.log('Ann error has occured'))
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
            .catch(err => console.error(err))
    }

    static bindEvents() {
        window.addEventListener('beforeunload', e => {
            this.disconnect()
        })
    }

    static encode(text, key) {
        if (key.length < 16) {
            console.log(`Encode error: key ${key} is too short`)
            key += new Array(16 - key.length).fill(0).join('')
        }
        let byteKey = aesjs.utils.utf8.toBytes(key).slice(0, 16)
        const textBytes = aesjs.utils.utf8.toBytes(text)
        const aesCtr = new aesjs.ModeOfOperation.ctr(byteKey, new aesjs.Counter(5))
        const encryptedBytes = aesCtr.encrypt(textBytes)
        const encryptedText = aesjs.utils.hex.fromBytes(encryptedBytes)
        return encryptedText
    }

    static decode(encodeText, key) {
        if (key.length < 16) {
            console.log(`Decode error: key ${key} is too short`)
            key += new Array(16 - key.length).fill(0).join('')
        }
        let byteKey = aesjs.utils.utf8.toBytes(key).slice(0, 16)
        const encryptedBytes = aesjs.utils.hex.toBytes(encodeText)
        const aesCtr = new aesjs.ModeOfOperation.ctr(byteKey, new aesjs.Counter(5))
        const decryptedBytes = aesCtr.decrypt(encryptedBytes)
        const decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes)
        return decryptedText
    }

    static isValidKey(key) {
        const templateRegex = /(\w{4}\-){3}\d+/gi
        const matchTemplate = key.match(templateRegex).length > 0
        const parts = key.split('-')
        const validKey = parts.length === 4 && (parts[0].charCodeAt(0) + parts[0].charCodeAt(1) == parts[3])
        return matchTemplate && validKey
    }

    static generatePrivateKey() {
        // Must be at least 16 characters long
        const privateKey = this.encode(this.encode(`${window.origin}&${Date.now()}`, this.serverUniqueKey), this.serverUniqueKey)
        return privateKey
    }
}