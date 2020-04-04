// © 2020 Dorian&Co All Rights Reserved

const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const auth = require('./src/auth')
const app = express()

const PORT = process.env.PORT || 8000


app.use(cors())
app.use(bodyParser.json())
app.use(express.urlencoded({ extended: true }))
app.use('/auth', auth.AuthSystem.handdleRoute)


app.listen(PORT)