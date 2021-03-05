# Lisco Framework

Framework nodejs con express y knex para el desarrollo de backends.


## Quick Setup

Install
``` javascript

npm install git+[lisco_url]

npm install esm dotenv

```

Runtime
``` javascript
require = require("esm")(module/*, options*/)

require('dotenv').config();
//module dependencies.
require('./index.js')(true).then(() => {
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
import { run_lisco, Logger, Server, ClusterServer, AuthController, JwtAuthHandler } from 'lisco'

module.exports = (withLog) => {
    return (async () => {
        await Logger.configure();

        const statics = {
            "/temp": "/temp"
        }
        const routes = [
            new AuthController([], new JwtAuthHandler()), //JWT Auth
        ];
        const server = new Server(statics, routes);
        server.customizeExpress = () => {
            // this.app.use(cookieParser())
        }

        run_lisco(server);

        ClusterServer.executeOnlyMain = () => {
            //Acciones a ejecutar sobre el mainWorker
            console.log("MainThread")
        }

        ClusterServer.start(withLog);
        ClusterServer.on('listening', () => {
            console.log('listening');
        })

    })();
};

```


.env
```
DEBUG=true
PORT=3700
CLUSTERED=false

DEFAULT_LANG='es'

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



