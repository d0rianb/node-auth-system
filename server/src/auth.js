const sha1 = require('sha1')
const aesjs = require('aes-js')

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

let clients = []

class AuthSystem {
    static handdleRoute(req, res, next) {
        const clientIP = req.header('x-forwarded-for') || req.connection.remoteAddress

        if (AuthClient.exist(clients, clientIP)) {
            let client = AuthClient.get(clients, clientIP)
            client.handdleRequest(req, res, next)
        } else {
            let client = new AuthClient(req)
            client.handdleRequest(req, res, next)
            clients.push(client)
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
}

class AuthClient {
    constructor(req) {
        this.clientReq = req
        this.ip = req.header('x-forwarded-for') || req.connection.remoteAddress
        this.uniqueKey = this.generateUniqueKey()
        this.privateKey = ''
        this.isAuthentified = false
    }

    static get(clientsList, ip) {
        return clientsList.filter(client => client.ip == ip)[0]
    }

    static exist(clientsList, ip) {
        return clientsList.filter(client => client.ip == ip).length > 0
    }

    handdleRequest(req, res, next) {
        const request = req.body.request

        if (!request) {
            console.log('error: no request')
            res.send({ error: 'Bad query : no request' })
        }

        switch (request) {
            case 'RequestUniqueKey':
                res.send({ uniqueKey: this.uniqueKey })
                break;
            case 'SendPrivateKey':
                this.privateKey = req.body.encode ? this.decode(req.body.privateKey, this.uniqueKey) : req.body.privateKey
                console.log(this.privateKey)
                res.json({
                    message: 'Authentification success',
                    success: true,
                    accessToken: this.generateToken()
                })
                this.isAuthentified = true
                break;
            default:
                console.log(request)
                res.json({ error: 'Unknow request' })
        }

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
            console.log('error generateUniqueKey')
        }
    }

    generateToken() {
        const token = this.encode('token', this.privateKey)
        return token
    }

    encode(text, key) {
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

    decode(encodeText, key) {
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

}

module.exports = {
    AuthSystem,
    AuthClient
}