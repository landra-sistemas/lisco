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
import { run_lisco, Logger, Server } from 'lisco'

module.exports = (withLog) => {
    return (async () => {
        await Logger.configure();

        const statics = {
            "/temp": "/temp"
        }
        const routes = [];
        const server = new Server(statics, routes);
        server.customizeExpress = () => {
            // this.app.use(cookieParser())
        }

        run_lisco(server);

        global.cluster_server.executeOnlyMain = () => {
            //Acciones a ejecutar sobre el mainWorker
            console.log("MainThread")
        }

        global.cluster_server.start(withLog);
        global.cluster_server.on('listening', () => {
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


```