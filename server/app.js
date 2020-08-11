// © 2020 Dorian&Co All Rights Reserved

const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const Logger = require('@dorianb/logger-js')
const AuthSystem = require('./src/auth')
const app = express()

const PORT = process.env.PORT || 8081
const DEBUG = true

if (DEBUG) Logger.clear('all')

app.use(cors())
app.use(bodyParser.json())
app.use(express.urlencoded({ extended: true }))
app.use('/auth', AuthSystem.handleRoute) // Handle auth routes
app.use(AuthSystem.secureRequest) // Only allow secure requests

AuthSystem.on('clientConnected', client => console.log(`${client.ip} connected`))
AuthSystem.on('clientDisconnected', client => console.log(`${client.ip} disconnected`))

app.post('/*', (req, res) => {
    if (!req.url.includes('auth')) console.log(`Clear content ${req.clearContent}`)
})

app.listen(PORT)