# Lisco Framework


![alt](./logo.png)

Framework nodejs con express y knex para el desarrollo de backends.


## Quick Setup

Install
``` javascript

npm install git+[lisco_url]

npm install esm dotenv

```

Runtime
``` javascript
//run.js

require = require("esm")(module/*, options*/)

require('dotenv').config();
//module dependencies.
require('./index.js')().then(() => {
    console.log("Started");
}).catch((ex) => {
    console.error(ex)
});

//Capturar errores perdidos
process.on('uncaughtException', (err) => {
    // handle the error safely
    console.error("Error: %s", err.stack || err.message);
});
```

Index
``` javascript
//index.js

import { App, AuthController, JwtAuthHandler } from 'lisco'

module.exports = async () => {

    App.customizeExpress = (app) => { };
    App.statics = {
        "/temp": "/temp"
    }
    App.routes = [
        //new AuthController([], new JwtAuthHandler()),
    ]

    App.executeOnlyMain = () => {
        //Acciones a ejecutar sobre el mainWorker
        console.log("MainThread")
    }

    await App.init();

    App.start();
    App.server.on('listening', () => {
        console.log('listening');
    })

};
```


.env
```
DEBUG=true
PORT=3700
CLUSTERED=false

DEFAULT_LANG='es'

DISABLE_LOGGER=false
REPL_ENABLED=true

# SSL
SSL=false
PORT_SSL=3443
SSL_CERT=null
SSL_KEY=null
SSL_PASS=null

# Password encryption (Run Utils.generateKeys())
CRYPT_IV=XXXX
CRYPT_SECRET=XXXX


# secret for encryption of jwt signature
JWT_SECRET=XXXXXX

# lifetime of the token (in seconds)
JWT_LIFETIME=86400

# algorithm used in token signing
JWT_ALGORITHM=HS256

JWT_AUDIENCE=MyAudience
JWT_ISSUER=Landra Sistemas
JWT_SUBJECT=MySub
```

``` json
//log4js.json
{
    "disableClustering": true,
    "appenders": {
        "application": {
            "type": "file",
            "filename": "logs/default.log",
            "maxLogSize": 10485760,
            "backups": 3,
            "compress": true
        },
        "out": {
            "type": "stdout"
        }
    },
    "categories": {
        "default": {
            "appenders": [
                "application",
                "out"
            ],
            "level": "trace"
        }
    }
}

```



## VSCode development

Para hacer que al ejecutar una aplicación los mensajes de log del `consoleApender` aparezcan en el modo debug es necesario configurar en el `launch.json` la ejecución como:

``` json

{
    "type": "node",
    "request": "launch",
    "name": "Launch Program",
    "cwd": "${workspaceFolder}/../lisco_tester",
    "program": "${workspaceFolder}/../lisco_tester/run.js",
    "outputCapture": "std"  /// <---- Esto es lo importante
}
```



## Ejemplos DB Connection

Ficheros -> ./dbconfig

KNEX -> [http://knexjs.org/#Installation](http://knexjs.org/#Installation)






### Monitoring

TODO intentar adaptar, aunque sea con un fork esto:

https://github.com/RafalWilinski/express-status-monitor

Al utilizar CDN's limita bastante el deploy del proyecto, pero con un fork podríamos hacer que utilizase dependencias locales.