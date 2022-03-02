# Lisco Framework


![alt](https://raw.githubusercontent.com/landra-sistemas/lisco/master/logo.png)

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



# Descripción de Componentes

## Rutas y Controladores

La aplicación carga todos los controladores añadidos a `App.routes` de forma secuencial.

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

## Autenticación

El framework implementa un sistema de validación de usuarios de forma nativa. Este sistema permite cargar múltiples métodos de autenticación en base a clases que cumplan un determinado patrón.

Actualmente existen dos implementaciones: JWT y Cookie


El controlador `AuthController` es el encargado de proporcionar la funcionalidad para la validación. Dispone de las siguientes rutas:

- `POST`: **/login** `{"username": "", "password": ""}` | Inicia Sesión validando los credenciales
- `POST`: **/logout** | Cierra la sesión

De forma automática, una vez configurado, este controlador escucha todas las solicitudes recibidas (a excepción de las marcadas como ignoradas) comprobando que la sesión proporcionada es válida.

Para habilitar el sistema es necesario añadir, como primera ruta, lo siguiente:

``` javascript
//index.js 

[...]

const publicPaths = [
    "/",
    "/login",
    "/translation",
    "/settings/load",
    "/menu",
    "/external"
]

App.routes = [
    new AuthController(publicPaths, new IAuthHandler(new UserDao())),
    [...]
]

[...]
``` 

- PublicPaths: Sirve para especificar aquellas rutas que no necesitan haber iniciado sesión para ejecutarse.
- `new AuthController`: Construye el controlador básico que recibe como parámetros la lista de rutas publicas y el manejador para la autenticación
- `new IAuthHandler`: Es necesario proporcionar una clase que extienda de IAuthHandler e implemente los métodos `validate` y `check`. 
- `new UserDao`: Es necesario proporcionar un Dao encargado del acceso a la tabla de usuarios y que como mínimo disponga de las columnas **username** y **password**.



### JWT Authentication

La implementación JWT utiliza los Json Web Token enviados como cabecera en la solicitud para validar los datos del usuario.

Basa su funcionamiento en la librería **jsonwebtoken** y utiliza los parámetros definidos en el archivo `.env` para funcionar.

Para utilizarla es necesario especificar como manejador la clase JwtAuthHandler:

``` javascript
App.routes = [
    new AuthController(publicPaths, new JwtAuthHandler(new UserDao())),
]
```

#### Token

El token será devuelto mediante la llamada `POST /login` descrita anteriormente. 

Este token será necesario proporcionarlo en la cabecera `Authorization: Bearer <token>` en todas las llamadas posteriores a la aplicación.

Este token almacena toda la información de la entidad usuario devuelta por la clase UserDao a excepción del campo `password`

### Cookie Authentication

Este sistema utiliza cookies para la gestión de las sesiones de la aplicación.

Utiliza el `cookie-parser` de express y para configurarlo es necesario:

1. Instalar:  connect-session-knex y express-session
2. Cargar la cookie store en express mediante el método `customizeExpress`
``` javascript
//Configurar la gestion de cookies
App.customizeExpress = (app) => {
    const KnexSessionStore = knexStore(session);

    app.use(session({
        store: new KnexSessionStore({
            knex: KnexConnector.connection,
            tablename: 'sessions_knex'
        }),
        secret: process.env.COOKIE_PASS,
        resave: true,
        rolling: true,
        httpOnly: true,
        saveUninitialized: true,
        cookie: { maxAge: (process.env.COOKIE_TIMEOUT || 3 * 60 * 60) * 1000 } // 1 Hour [30 days -> (30 * 24 * 60 * 60 * 1000)]
    }));
};
```
3. Añadir al archivo `.env` los parámetros `COOKIE_PASS` y `COOKIE_TIMEOUT`
4. Cargar el controlador:
``` javascript
App.routes = [
    new AuthController(publicPaths, new CookieAuthHandler(new UserDao()))
]
``` 

#### Cookie

La cookie se almacenará, mediante esta configuración, en una tabla de postgre. Esto permitirá desplegar la aplicación en cluster ya que se comparte una store común.

Esta cookie dispondrá de los datos devueltos por la clase UserDao a excepción del campo `password`.



## Logger

El sistema de log de la aplicación utiliza `log4js` como base. Se ha simplificado el uso de la aplicación sobreescribiendo el objeto global `console`.

El sistema esta habilitado por defecto y se utiliza de la siguiente forma:

```
console.log(mensaje)
console.error(mensaje)
console.info(mensaje)
console.debug(mensaje)
console.custom(level, mensaje)
```


El sistema se configura mediante el fichero `log4js.json` situado en la raíz del proyecto el cual permite configurar los appender y los niveles de log para cada uno. Mas información sobre la configuración: [https://log4js-node.github.io/log4js-node/index.html](https://log4js-node.github.io/log4js-node/index.html)


## Traducciones

El sistema de traducciones utiliza archivos `json` en los que se almacenan las claves y los valores de las traducciones.

Este sistema dispone del parámetro **DEFAULT_LANG** el cual define el idioma por defecto y permite cargar cualquier archivo json situado en la carpeta **i18n** del proyecto.

Los archivos han de nombrarse de la siguiente forma: `lang_[XX].json`

Siendo `[XX]` el código del idioma

El método `App.i18n.load(XX)` carga el idioma recibido como parámetro.

El método `App.i18n.translate(key, [lang])` traduce una clave en base al idioma proporcionado. Se usa el idioma por defecto en caso de no proporcionarlo.


## Eventos

 La aplicación dispone de un sistema encargado de gestionar eventos. Este sistema permite que los diferentes procesos del modo `clustered` se comuniquen entre si.

 Para iniciar la escucha de un evento es necesario:
 ``` javascript
import { App } from 'lisco'

App.events.on('custom', function cosa(props) {
    console.log(props);
})
 ```

Esto implica que la aplicación comienza a escuchar el evento 'custom' con unos parámetros y los mostrará en el log.

Para ejecutar un evento desde otro punto de la aplicación es necesario:

 ``` javascript
import { App } from 'lisco'

App.events.emit('custom', { test: "test" })
 ```

 Esto lanza el evento con los parámetros `{ test: "test" }`.

## Filtros

La clase `KnexFilterParser`  convierte un objeto clave valor en un conjunto de filtros.
     
- Filtro estandar:
``` json
"filters": {
    "column": "value" // filtro generico exact
}
```
- Filtro Objeto:
``` json
"filters": {
    "column": {
        "type": "date|between|exists|notexists|greater|greaterEq|less|lessEq|exact|exactI|not|null|notnull|like|likeI",
        "start": "xxx", //inicio de rango para el filtro de date y between
        "end": "xxx", //fin de rango para el filtro date y between
        "value": "xxx" //valor a utilizar para el resto de filtros
    }
}
```
- Filtro Lista:
``` json
"filters": {
    "column": [1, 2, 3]
}
// Filtro de tipo IN, todos los elementos que coincidan
```

      
- Definicion de tipos:
    - **date**: filtro de fechas desde y hasta
    - **between**: filtro entre dos valores concretos
    - **exists**: busca si existe la propiedad
    - **notexists**: busca si existe la propiedad
    - **greater**: mayor que
    - **greaterEq**: mayor o igual que
    - **less**: menor que
    - **lessEq**: menor o igual que
    - **exact**: valor exacto
    - **exactI**: valor exacto ignorando mayusculas y minusculas
    - **not**: distinto de
    - **null**: igual a null
    - **notnull**: distinto de null
    - **like**: filtro like
    - **likeI**: filtro like ignorando mayusculas y minusculas
 