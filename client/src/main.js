const SERVER_URL = '127.0.0.1'
const PORT = 8081

const AUTH_URL = `http://${SERVER_URL}:${PORT}/auth`
const TIMEOUT_LIMIT = 1000 // ms

// TODO:
//  - Better library style API :
//      - Getter & setter
//      - jsdoc ?
//      - handler functions

class Auth {
    static async authenticate() {
        await this.request('RequestUniqueKey')
            .then(res => {
                // Receive serverUniqueKey
                if (res.uniqueKey && this.isValidKey(res.uniqueKey)) {
                    this.serverUniqueKey = res.uniqueKey
                    return true
                } else {
                    throw new ResponseError('Error with unique key')
                }
            })
            .then(() => {
                // Send privateKey
                this.privateKey = Auth.generatePrivateKey()
                return this.request('SendPrivateKey', {
                    encode: 'uniqueKey',
                    privateKey: this.encode(this.privateKey, this.serverUniqueKey)
                })
            })
            .then(res => {
                if (res.success && res.accessToken) {
                    this.isAuthentified = true
                    this.accessToken = this.decode(res.accessToken, this.privateKey)
                    this.accessTokenInfo = JSON.parse(this.decode(this.accessToken, this.privateKey))
                    console.log('connected')
                    Auth.bindEvents()
                } else {
                    throw new ResponseError('Error with the token')
                }
            })
    }

    static async disconnect() {
        if (!this.isAuthentified) return
        this.request('Disconnect')
            .then(res => {
                if (res.disconnected) {
                    this.isAuthentified = false
                    console.log('Disconnection successfull')
                } else {
                    throw new ResponseError('Disconnection error')
                }
            })
            .catch(err => {
                throw new ResponseError('Disconnection error')
            })
    }

    static async request(reqName, params) {
        this.timeout = setTimeout(() => {
            throw new Error('Timeout')
        }, TIMEOUT_LIMIT)
        return await fetch(`${AUTH_URL}`, {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    request: reqName,
                    ...params
                })
            })
            .then(data => {
                clearTimeout(this.timeout)
                return data.json()
            })
            .catch(err => {
                throw new ResponseError(err)
            })
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

class AuthError extends Error {
    constructor(msg, ...args) {
        super(msg, ...args)
    }
}

class TimeoutError extends Error {
    constructor(msg, ...args) {
        super(msg, ...args)
    }
}

class ResponseError extends Error {
    constructor(msg, ...args) {
        super(msg, ...args)
    }
}

async function request(url, method, body) {
    if (!Auth.isAuthentified) throw new AuthError('Not authentified')
    const secureBody = Auth.encode(JSON.stringify(body), Auth.accessToken)
    timeout = setTimeout(() => {
        throw new TimeoutError(`Timeout during ${method} request of ${JSON.stringify(body)} to ${url}`)
    }, TIMEOUT_LIMIT)
    return await fetch(url, {
        method: method,
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            encoded: true,
            content: secureBody
        })
    })
    .then(data => {
            clearTimeout(timeout)
            return data.json()
        })
    .catch(err => {
        throw new ResponseError(err)
    })
}

function testSecureRequest() {
    request(`http://${SERVER_URL}:${PORT}`, 'POST', {
        str: 'oui',
        int: 1,
        obj: {}
    })
}

function testUnsecureRequest() {
    fetch(`http://${SERVER_URL}:${PORT}`, {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                content: {
                    str: 'oui',
                    int: 1,
                    obj: {}
                }
            })
        })
        .then(data => data.text())
        .catch(err => console.error(err))
}