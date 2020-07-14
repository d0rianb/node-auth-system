// © 2020 Dorian&Co All Rights Reserved

const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const AuthSystem = require('./src/auth')
const app = express()

const PORT = process.env.PORT || 8081


app.use(cors())
app.use(bodyParser.json())
app.use(express.urlencoded({ extended: true }))
app.use('/auth', AuthSystem.handleRoute)


app.listen(PORT)