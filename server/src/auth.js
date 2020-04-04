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

const message = {
    header: {
        // some headers
    },
    body: {
        isCrypted: true,
        request: 'RequestUniqueKey',
        content: ''
    }
}

let clients = []

class AuthSystem {
    static handdleRoute(req, res, next) {
        const clientIP = req.header('x-forwarded-for') || req.connection.remoteAddress

        if (Client.exist(clients, clientIP)) {
            let client = Client.get(clients, clientIP)
            client.handdleRequest(req, res, next)
        } else {
            let client = new Client(req)
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

class Client {
    constructor(req) {
        this.clientReq = req
        this.ip = req.header('x-forwarded-for') || req.connection.remoteAddress
        this.uniqueKey = this.generateUniqueKey()
        this.privateKey = ''
        this.authenticate = false
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
                res.json({
                    message: 'Authentification success',
                    success: true,
                    accessToken: this.generateToken()
                })
                this.authenticate = true
                break;
            default:
                console.log(request)
                res.json({ error: 'Unknow request' })
        }

    }

    generateUniqueKey() {
        return 'dorian09876543'
    }

    generateToken() {
        return 'CustomToken id expire | encode ' + this.privateKey
    }

}

module.exports = {
    AuthSystem,
    Client
}