const sha1 = require('sha1')
const aesjs = require('aes-js')
const Logger = require('@dorianb/logger-js')

/**
 *  1) client send request to get unique key - clear
 *  2) server generate & send unique key - clear
 *  3) client generate private key & send it to the server - unique crypted
 *  4) server accept private key & okmessage - private crypted
 *  5) client send info -  private crypted
 */


/** Client side request        Server side request
 *  1) RequestUniqueKey          1) RequestPrivateKey
 *  2) SendPrivateKey            2) Send AuthValidation
 *  3) SendInformations
 */

class AuthSystem {
    static handleRoute(req, res, next) {
        const clientIP = req.header('x-forwarded-for') || req.connection.remoteAddress

        if (AuthSystem.exist(clientIP)) {
            let client = AuthSystem.get(clientIP)
            client.handdleRequest(req, res, next)
        } else {
            let client = new AuthClient(req)
            client.handdleRequest(req, res, next)
            AuthSystem.addClient(client)
        }

        // res.json({
        //     body: req.body,
        //     query: req.query,
        //     baseUrl: req.baseUrl,
        //     originalUrl: req.originalUrl,
        //     url: req.url,
        //     method: req.method,
        //     headers: req.headers,
        //     params: req.params,
        //     trailers: req.trailers,
        // })
        // console.log(Object.keys(req))
    }

    static secureRequest(req, res, next) {
        if (req.url.includes('auth')) next()
        else if (req.body.encoded && req.body.content) {
            console.log('encoded request')
            const clientIP = req.header('x-forwarded-for') || req.connection.remoteAddress
            if (AuthSystem.exist(clientIP)) {
                const client = AuthSystem.get(clientIP)
                req.clearContent = client.decode(req.body.content, client.accessToken)
                next()
            }
        } else {
            console.log('unsecure request')
        }
    }

    static get(ip) {
        return this.getClients().find(client => client.ip == ip)
    }

    static exist(ip) {
        return this.getClients().filter(client => client.ip == ip).length > 0
    }

    /* Array of all the clients, even not authenticate ones */
    static getClients() {
        if (!this.clients) this.clients = []
        return this.clients
    }

    static getAuthenticatedClients() {
        return AuthSystem.getClients().filter(client => client.isAuthentified)
    }

    static addClient(client) {
        AuthSystem.getClients().push(client)
    }

    static removeClient(client) {
        if (!this.clients) return
        client.isAuthentified = false
        client.privateKey = ''
        this.clients = this.clients.filter(x => x !== client)
    }
}

class AuthClient {
    constructor(req) {
        this.clientReq = req
        this.ip = req.header('x-forwarded-for') || req.connection.remoteAddress
        this.uniqueKey = this.generateUniqueKey()
        this.privateKey = ''
        this.accessToken = ''
        this.isAuthentified = false
        Logger.setOptions({ filename: 'auth.log' })
    }

    handdleRequest(req, res, next) {
        const request = req.body.request

        if (!request) {
            Logger.error(`Bad query : no request - client ${this.uniqueKey} [${this.ip}]`, 'requests.log')
            res.send({ error: 'Bad query : no request' })
        }

        switch (request) {
            case 'RequestUniqueKey':
                res.json({ uniqueKey: this.uniqueKey })
                break
            case 'SendPrivateKey':
                this.privateKey = req.body.encode == 'uniqueKey' ? this.decode(req.body.privateKey, this.uniqueKey) : req.body.privateKey
                this.accessToken = this.encode(this.generateToken(), this.privateKey)
                res.json({
                    message: 'Authentification success',
                    success: true,
                    accessToken: this.accessToken
                })
                Logger.info(`Client ${this.uniqueKey} at [${this.ip}] connected`, 'client.log')
                this.isAuthentified = true
                break
            case 'Disconnect':
                AuthSystem.removeClient(this)
                res.json({ disconnected: true })
                Logger.info(`Client ${this.uniqueKey} at [${this.ip}] disconnected`, 'client.log')
                break
            default:
                Logger.error(`Unknow request : ${request} from client ${this.uniqueKey} at [${this.ip}]`, 'requests.log')
                res.json({ error: 'Unknow request' })
                break
        }
        next()
    }

    generateUniqueKey() {
        // key : a17d-d8fg-1b3n-145
        const templateRegex = /\w{4}/g
        const clearKey = sha1(`${this.ip}@${Date.now()}`)
        const template = clearKey.match(templateRegex)
        if (template.length >= 3) {
            const uniqueKey = template.slice(0, 3).join('-')
            const verificationCode = uniqueKey.charCodeAt(0) + uniqueKey.charCodeAt(1)
            return `${uniqueKey}-${verificationCode}`
        } else {
            Logger.error('error generateUniqueKey - template is too short')
        }
    }

    generateToken() {
        const tokenDuration = 1 * 3600 * 1000 // ms --> 1h
        const token = JSON.stringify({
            scope: 'all',
            clientPrivate: this.privateKey,
            duration: tokenDuration,
            expireDate: Date.now() + tokenDuration
        })
        const tokenEncode = this.encode(token, this.privateKey)
        return tokenEncode
    }

    encode(text, key) {
        if (key.length < 16) {
            Logger.warn(`Encode error: key ${key} is too short`)
            key += new Array(16 - key.length).fill(0).join('')
        }
        let byteKey = aesjs.utils.utf8.toBytes(key).slice(0, 16)
        const textBytes = aesjs.utils.utf8.toBytes(text)
        const aesCtr = new aesjs.ModeOfOperation.ctr(byteKey, new aesjs.Counter(5))
        const encryptedBytes = aesCtr.encrypt(textBytes)
        const encryptedText = aesjs.utils.hex.fromBytes(encryptedBytes)
        return encryptedText
    }

    decode(encodeText, key) {
        if (key.length < 16) {
            Logger.warn(`Decode error: key ${key} is too short`)
            key += new Array(16 - key.length).fill(0).join('')
        }
        const byteKey = aesjs.utils.utf8.toBytes(key).slice(0, 16)
        const encryptedBytes = aesjs.utils.hex.toBytes(encodeText)
        const aesCtr = new aesjs.ModeOfOperation.ctr(byteKey, new aesjs.Counter(5))
        const decryptedBytes = aesCtr.decrypt(encryptedBytes)
        const decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes)
        return decryptedText
    }

}

module.exports = AuthSystem