# Node authentification system

`node-auth-system` is a npm logger library for NodeJS

This project is part of the [vener.fr](http://www.vener.fr) project, to handle authentification of the server ([express](https://www.expressjs.com)).


## Installation
To install the package, just run :
```bash
npm install --save @dorianb/...
```

Then in the `client` file :
```js
// To be defined, unclear for now
```

In the `server` file :
```js
const auth = require('./src/auth')
const app = require('express')()

app.use('/auth', auth.AuthSystem.handdleRoute)
```

* * *

2020 &copy; Dorian Beauchesne
