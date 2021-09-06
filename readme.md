# Lisco Framework


![alt](./logo.png)

Framework nodejs con express y knex para el desarrollo de backends.


## Quick Setup

Install
``` shell

> npm install lisco

> npm install esm dotenv

```

Runtime principal. Archivo desde el que se arranca el proyecto.

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
    console.error(`Error: ${err || err.stack || err.message}`);
});
```

Archivo index encargado de aplicar la configuración
``` javascript
//index.js

import { App } from 'lisco'

module.exports = async () => {

    App.customizeExpress = (app) => { };
    App.statics = {
        "/temp": "/temp"
    }
    App.routes = [
        //new CustomController()
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


Archivo `.env` con las configuraciones de inicio
``` properties
# Determina el scope actual del producto (development, production)
NODE_ENV=development
# Puerto http en el que se desplegará la aplicación
PORT=3700
# (Opcional) Habilita el modo cluster de forma que se arranquen multiples workers
CLUSTERED=false
# Idioma por defecto de la aplicación
DEFAULT_LANG='es'
# (Opcional) Deshabilita el logger para la ejecución de testing 
DISABLE_LOGGER=false
# (Opcional) Habilita la consola remota accesible mediante telnet o lisco_terminal
REPL_ENABLED=true
# (Opcional) Determina el puerto en el que se desplegará la terminal remota
REPL_PORT=5001

# (Opcional) Habilita el servidor SSL 
SSL=false
# (Opcional) Puerto en el que se desplegará el servidor Https
PORT_SSL=3443
# (Opcional) Ruta donde se encuentra el archivo del certificado (por defecto ./cert.pem)
SSL_CERT=null
# (Opcional) Ruta donde se encuentra el archivo key (por defecto ./key.pem)
SSL_KEY=null
# Contraseña establecida en el certificado (Necesaria si se utilizan los anteriores)
SSL_PASS=null

# Password encryption (Run Utils.generateKeys())
CRYPT_IV=XXXX
CRYPT_SECRET=XXXX


# secret for encryption of jwt signature
JWT_SECRET=XXXXXX
# lifetime of the token (in seconds or string representing time)
JWT_EXPIRES="2 days"
# algorithm used in token signing
JWT_ALGORITHM=HS256
# audience for the token 
JWT_AUDIENCE=MyAudience
# issuer of the token
JWT_ISSUER=Landra Sistemas
# subject of the token
JWT_SUBJECT=MySub
```

Archivo `log4js.json` encargado de la configuración del logger.
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




## Arranque del proyecto

```
> node run.js

[2021-03-06T19:39:52.987] [INFO] log - MainThread
[2021-03-06T19:39:53.061] [INFO] log - Started
[2021-03-06T19:39:53.062] [INFO] log - Server Worker running on port: 3700!
[2021-03-06T19:39:53.063] [INFO] log - listening

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


## Siguientes pasos

### Creación de controladores

Un controlador se encarga de desplegar rutas para construir la Api. Existen dos formas de crear un controlador:

- Extender de **BaseController**
- Crear uno **personalizado**


Al extender de BaseController se proporciona una interfaz genérica CRUD sobre una entidad concreta.

Por ejemplo si hablamos de la tabla `user` crearíamos

``` javascript
import { BaseController, BaseService } from 'lisco'

export default class UserController extends BaseController {
    configure() { //Necesario
        super.configure('user', { service: BaseService, table: 'user' });

        
        return this.router;
    }
}
```

Mediante estas cuatro lineas dispondríamos de los siguientes métodos:

- `POST` /user/list -> Listar usuarios
- `GET` /user/:id -> Obtener usuario
- `POST` /user -> Crear usuario
- `PUT` /user/:id -> Modificar usuario
- `DELETE` /user/:id -> Borrar usuario


Sobre este controlador se podrían crear nuevas rutas para la realización de acciones personalizadas o incluso sobreescribir algunas de ellas.

Ejemplo

``` javascript
export default class UserController extends BaseController {
    configure() { //Necesario
        super.configure('user', { service: BaseService, table: 'user' });

        this.router.get('/session', asyncHandler((res, req, next) => { this.getSession(res, req, next); }));

        return this.router;
    }

    async getSession(request, response) {
        if (request.session.username) {
            /* CUSTOM CODE */
            response.json(jsRes.toJson());
        }
    }
}
```

El proceso de creación de un controlador **personalizado** es el mismo que el descrito anteriormente. La única diferencia es que este no tendría que extender de `BaseController` ni llamar al método `super.configure`.

El único criterio para que un controlador pueda ser utilizado por la aplicación es que disponga de un método `configure` y este devuelva un `router` de express (`this.router = express.Router();`)

Visualizar el código de `BaseController` puede ayudar a la creación de controladores personalizados.


Durante estos ejemplos se ha utilizado `BaseService` su funcionamiento es similar a lo descrito con el `BaseController` este utiliza el `BaseDaoKnex` para la ejecución de los métodos CRUD básicos.






## Configuración de BD y migraciones

Crear un archivo `knex-cli.js` en la raíz del proyecto con el siguiente contenido:

``` javascript
var migrate = require('knex/bin/cli');

```


Necesario crear un knexfile con los datos de conexión a BD.

``` shell
> node knex-cli init

```

Esto creará un archivo similar a:

``` javascript
// Update with your config settings.

module.exports = {

    development: {
        client: 'sqlite3',
        connection: {
            filename: './dev.sqlite3'
        },
        migrations: {
            tableName: 'knex_migrations'
        }
    },


    production: {
        client: 'mysql',
        connection: {
            database: 'database',
            user: 'username',
            password: 'password'
        },
        pool: {
            min: 2,
            max: 10
        },
        migrations: {
            tableName: 'knex_migrations'
        }
    }

};
```

Conectarse a la base de datos añadiendo al `index.js` de la aplicaciión:

``` javascript
//index.js

//Antes de App.start()

    KnexConnector.init(require('./knexfile').development);

    //Esto habilita una conexión (o pool) accesible mediante el singleton KnexConnector. Para ello:

    KnexConnector.connection.[...] // Insert, Where, etc...


```




### Mas info KNEX
[http://knexjs.org/#Installation](http://knexjs.org/#Installation)




## Monitoring

TODO intentar adaptar, aunque sea con un fork esto:

https://github.com/RafalWilinski/express-status-monitor

Al utilizar CDN's limita bastante el deploy del proyecto, pero con un fork podríamos hacer que utilizase dependencias locales.
