# Lisco Framework

![npm](https://img.shields.io/npm/v/@landra_sistemas/lisco?label=version)
![GitHub](https://img.shields.io/github/license/landra-sistemas/lisco)

![alt](https://raw.githubusercontent.com/landra-sistemas/lisco/master/logo.png)

Node.js framework with express and knex for backend development.


- [Lisco Framework](#lisco-framework)
  - [Quick Setup](#quick-setup)
  - [Project Startup](#project-startup)
  - [VSCode development](#vscode-development)
  - [DB Configuration and Migrations](#db-configuration-and-migrations)
    - [Running migrations on startup](#running-migrations-on-startup)
    - [More info KNEX](#more-info-knex)
- [Component Description](#component-description)
  - [Routes and Controllers](#routes-and-controllers)
    - [Shorthands](#shorthands)
    - [Autoconfig](#autoconfig)
    - [Validation](#validation)
  - [Authentication](#authentication)
    - [JWT Authentication](#jwt-authentication)
      - [Token](#token)
    - [Cookie Authentication](#cookie-authentication)
      - [Cookie](#cookie)
    - [Keycloak Authentication](#keycloak-authentication)
      - [Usage](#usage)
  - [Logger](#logger)
  - [Translations](#translations)
  - [Events](#events)
  - [Filters](#filters)
    - [Sorting](#sorting) 
  - [Server Views](#server-views)
  - [Runtime CLI](#runtime-cli)
    - [Additional options](#additional-options)
  - [Server Monitoring](#server-monitoring)
  - [SocketIO](#socketio)



## Quick Setup
Start a blank project

``` shell
> npm init
```
> Enter project info

Install the needed dependencies
``` shell

> npm install @landra_sistemas/lisco dotenv-defaults

```


`index.js` file is responsible for applying configuration and initializing components.

**index.js**
``` javascript
import { config } from 'dotenv-defaults';
import { App } from '@landra_sistemas/lisco'
//const { config } = require('dotenv-defaults') -> common js
//const { App } = require('@landra_sistemas/lisco') -> common js

//dotenv
config();

const main = async () => {
    App.runtime(); //(Optional) Start the cli runtime

    App.customizeExpress = (app) => { 
        // Add here custom express options
    };
    App.statics = { //Static files to serve
        "/temp": "/temp"
    }
    App.routes = [ //Loaded controllers
        //new CustomController()
    ]

    App.executeOnlyMain = () => { 
        //mainWorker executed actions. Useful to execute things once in cluster mode.
        console.log("MainThread")
    }

    await App.init(); //Inits the configuration with the provided params

    App.start(); //Starts the server
    App.server.on('listening', () => {
        //This event is triggered once the server is running
        console.log('listening');
    })
};

main();

//!! //!! It's recommended to use handlers for unhandled exceptions:
process.on("uncaughtException", (err) => {
    // handle the error safely
    console.error(`Error: ${err || err.stack || err.message}`);
});
process.on("unhandledPromiseException", (err) => {
    // handle the error safely
    console.error(`Error: ${err || err.stack || err.message}`);
});

```


> **Optional: ESM**
> 
>  Node.js already has native support for resolving imports but in certain scenarios it may be necessary.
> 
> ``` bash
> > npm install esm
> ```
> 
> Then start the project from a file before index.js.  
> **Modify package.json so the start script points to this file.**
>
> **run.js**
> ``` javascript
> require = require("esm")(module/*, options*/) // -> Not required if CommonJS is being used or if the type: moodule is configured in the package json file.
> 
> //module dependencies.
> require('./index.js')().then(() => {
>     console.log("Started");
> }).catch((ex) => {
>     console.error(ex)
> });
> 
> //Move the handlers from index.js to here:
> process.on('uncaughtException', (err) => {
>     // handle the error safely
>     console.error(`Error: ${err || err.stack || err.message}`);
> });
> process.on('unhandledPromiseException', (err) => {
>     // handle the error safely
>     console.error(`Error: ${err || err.stack || err.message}`);
> });
> 
> ```

`.env` and `.env.defaults` have the init configurations

**.env**
``` properties
# Project environment scope (development, production)
NODE_ENV=development
# Http port
PORT=3700
# (Optional) Enables clustered mode. The app will be deployed starting multiple workers
CLUSTERED=false
# Default language
DEFAULT_LANG='es'
# (Optional) Disables logger for testing execution 
DISABLE_LOGGER=false
# (Optional) Enables remote console by telnet or lisco_terminal
REPL_ENABLED=false
# (Optional) Sets the remote console port
REPL_PORT=5001

# (Optional) Enables the SSL (https) server
SSL=false
# (Optional) https port
PORT_SSL=3443
# (Optional) SSL certificate path (defaults to ./cert.pem)
SSL_CERT=null
# (Optional) SSL key path (defaults to ./key.pem)
SSL_KEY=null
# Cert's SSL password (Not needed if the above are used)
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

> The `.env.defaults` file contains default configurations. This file **must be committed** and serves as the base for all environments.


**log4js.json** configures the logger. More info at: https://log4js-node.github.io/log4js-node/index.html

```json
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
> This file is mandatory. Without it, the app will not start.

## Project Startup

``` bash
> node run.js or npm start

[2021-03-06T19:39:52.987] [INFO] log - MainThread
[2021-03-06T19:39:53.061] [INFO] log - Started
[2021-03-06T19:39:53.062] [INFO] log - Server Worker running on port: 3700!
[2021-03-06T19:39:53.063] [INFO] log - listening

```

## VSCode development

To display log messages in debug mode setup `launch.json` like:

``` json

{
    "type": "node",
    "request": "launch",
    "name": "Launch Program",
    "cwd": "${workspaceFolder}/../lisco_tester",
    "program": "${workspaceFolder}/../lisco_tester/run.js",
    "outputCapture": "std"  /// <---- This is the important property!
}
```

## DB Configuration and Migrations

Create a knexfile with DB connection:

```shell
> ./node_modules/.bin/knex init
```

This will create something like:

``` javascript
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

Also, add this to the `index.js` file to connect to the database:

**index.js**
``` javascript

    import knexfile from "./knexfile.js";
    //const knexfile = require('./knexfile'); -> common js

    [...] //Antes del App.init()
    KnexConnector.init(knexfile[process.env.NODE_ENV]);
    await KnexConnector.test(); //Checks the DB connection

    [...]

    //
    

```

This opens a connection (or pool, if available) through the KnexConnector singleton. This instance can be accessed from anywhere in the project, but it's strongly recommended to access it only in the repository/DAO layer.

Code snippet example for database queries:
``` javascript
import {KnexConnector} from '@landra_sistemas/lisco';
//const {KnexConnector} = require("@landra_sistemas/lisco");

    [...]
    KnexConnector.connection.[...] // Insert, Where, etc...
    [...]
```
> `connection` is a knex instance containing all the methods, like `.from`, `.where`, etc. defined in its API.


### Running migrations on startup

Once the database connection is set up, right after the connection method in `index` file, the app is capable of running migrations as it follows:

```js
    [...] //Before App.init()
    try {
        await KnexConnector.connection.migrate.latest();
    } catch (e) {
        console.log("Error running migrations:",e);
    }
    [...]

    //
```

### KNEX info
[http://knexjs.org/#Installation](http://knexjs.org/#Installation)

# Component Description

## Routes and Controllers

The app loads all controllers in `App.routes` sequentially.  

Controllers define API routes. Options:
- Extend **BaseController**
- Create a **custom** one

Example with `user` table:

``` javascript
import { BaseController, BaseService } from '@landra_sistemas/lisco'

export default class UserController extends BaseController {

    configure() { //This method is mandatory, as it returns the router object.
        super.configure('user', { service: BaseService, table: 'user' });
        
        return this.router;
    }
}
```

This provides:
- `POST` /user/list -> List users
- `GET` /user/:id -> Get user
- `POST` /user -> Create user
- `PUT` /user/:id -> Update user
- `DELETE` /user/:id -> Delete user

Custom routes can be added or overridden.

Example

``` javascript
export default class UserController extends BaseController {
    configure() { //Mandatory
        super.configure('user', { service: BaseService, table: 'user', schema: yupSchema /*See validation*/ });

        this.router.get('/session',Utils.expressHandler((...args) => { 
            this.getSession(...args); 
        }));

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

Custom controllers must implement `configure()` returning an express router. The only difference is that they are not required to extend from `BaseController` and to call `super.configure`. You can check the `BaseController` code in order to learn how to implement custom controllers.

`BaseService` works similarly, providing CRUD via `BaseDaoKnex`.


### Shorthands

Since version `0.2.1-rc.0`, controllers can define simplified routes using `routes` property.

``` javascript
class HomeController extends BaseController {
    routes = {
        "/": {
            get: this.home.bind(this),
        },
    };

    // If the linter doesn't support class attributes:
    // constructor() {
    //     super();
    //     this.routes = {
    //         "/": {
    //             get: this.home.bind(this),
    //         },
    //     };
    // }

    home(req, res) {
        res.send("Hello world!");
    }
}
```

Sintax is as simple as an object with paths as keys and values as objects containing the request method.

``` javascript
{
    "/": {
        "get": this.home.bind(this),
        "post": this.method2.bind(this)
    },
    "/path/:id": {
        "get": this.method3.bind(this),
    }
}
```

Particularities:
- Shorthand routes load **after** `configure()`.
- No need to define `configure()`.
- Must extend `BaseController`.
- Double callbacks are supported modifying the sintax as: `"get": [keycloak.protect(...), this.method.bind(this)]`. **Only two elements allowed!**

### Autoconfig

Since version `0.2.1-rc.1`, automatic CRUD configuration is possible:

For this, controller must be defined with the following properties:
``` js
entity = "entity_name";
service = BaseService; //Class extending base service to perform operations
table = "table_name";
```

So the class will look like:

``` js
class HomeController extends BaseController {
    entity = "user";
    service = UserService;
    table = "user";
    schema: yupSchema /*See validation*/

    //  If the linter doesn't support class attributes:
    // constructor() {
    //     super();
    //     this.entity = "user";
    //     this.service = UserService;
    //     this.table = "user";
    //     this.schema= yupSchema /*See validation*/
    // }
}

``` 
### Validation

Input validation can be set up using `yup` library at `BaseController` level. Example schema:

``` js

const userSchema = object(    {
    name: string().required(),
    age: number().required().positive().integer(),
    email: string().email(),
});

```
This schema will be always used, if assigned to the `BaseController`, in the created and update methods.

## Authentication

Framework provides built-in user validation. Supports multiple strategies: JWT and Cookie.

`AuthController` handles:

- `POST`: **/login** `{"username": "", "password": ""}` | Logs is checking the credentials
- `POST`: **/logout** | Logs out

Once configured, this automatically listens all que requests (unless whitelisted) and valitates the session.

To enable this, it's necessary to add the following as the first path:

**index.js** 
``` javascript
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

- PublicPaths: this allows to whitelist paths from authentication.
- `new AuthController`: instantiates the basic controller and receives the public paths and authentication handler as params.
- `new IAuthHandler`: It's mandatory to provide a class extending `IAuthHandler`, implementing `validate` and `check` methods. 
- `new UserDao`: It's mandatory to provide a Dao for the `user` table handling with at least the **username** and **password** columns.

### JWT Authentication

The implementation uses the JWT params in the request header to validate the user credentials.

Uses `jsonwebtoken` and `.env` parameters.  

Configure with:

``` javascript
App.routes = [
    new AuthController(publicPaths, new JwtAuthHandler(new UserDao())),
]
```

#### Token

Returned by `POST /login`. 

Must be provided in header `Authorization: Bearer <token>` in subsequent requests.

This token includes all the info of the `user` entity, except the `password` field.

### Cookie Authentication

This implementation uses cookies to handle user sessions.

Config steps:
1. Install `connect-session-knex` and `express-session`
2. Configure session in `customizeExpress`
``` javascript
import { ConnectSessionKnexStore }  from "connect-session-knex";

//Configure cookie handling
App.customizeExpress = (app) => {
    app.use(session({
        store: new ConnectSessionKnexStore({
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
3. Add `.env` vars `COOKIE_PASS` and `COOKIE_TIMEOUT`
4. Load controller
``` javascript
App.routes = [
    new AuthController(publicPaths, new CookieAuthHandler(new UserDao()))
]
``` 

#### Cookie

The cookie will be stored in a database table. This will allow the app's clustered execution. This cookie includes all the info of the `user` entity, except the `password` field.

### Keycloak Authentication

Keycloak is an external user federation system.

Its lisco integration can be set up as follows:

``` bash
> npm install keycloak-connect@x.x.x //Keycloak version
```

Once installed, add a `config` folder at project's root level with the following content:

`keycloak-config.js`
```javascript
import Keycloak from "keycloak-connect";
import { App } from "@landra_sistemas/lisco";

let _keycloak;

function initKeycloak() {
    var keycloakConfig = {
        realm: process.env.KEYCLOAK_REALM,
        "auth-server-url": process.env.KEYCLOAK_REDIRECT_URL,
        "ssl-required": "external",
        resource: process.env.KEYCLOAK_BACK_CLI,
        "public-client": true,
        "confidential-port": 0,
    };

    if (_keycloak) {
        console.warn("Trying to init Keycloak again!");
    } else {
        console.log("Initializing Keycloak...");
        _keycloak = new Keycloak({}, keycloakConfig);
    }
}

function getKeycloak() {
    if (!_keycloak) {
        console.error("Keycloak has not been initialized. Please called init first.");
    }
    return _keycloak;
}

export { initKeycloak, getKeycloak };

```

Update `index.js` to init Keycloak and attach middleware.

``` javascript
import { initKeycloak, getKeycloak } from "./config/keycloak-config";

[...]
     App.customizeExpress = async (app) => {
        [...]
        //Inicializa keycloak
        initKeycloak();

         /**
         * Current keycloak
         * @type {Keycloak}
         * @public
         */
        App.keycloak = getKeycloak();
        app.use(App.keycloak.middleware({ logout: "/logout" }));
        [...]
    };
[...]
```

Add to `.env`:

```
#Keycloak
KEYCLOAK_REDIRECT_URL=http://localhost:3114/auth
KEYCLOAK_REALM=REALMNAME
KEYCLOAK_BACK_CLI=backend-client
```
#### Usage

To protect routes with roles:

``` javascript
this.router.get(
    "/login",
    App.keycloak.protect("realm:rolename"),
    exAsync((...args) => this.login(...args))
);
```
`//TODO add Keycloak login documentation`

For more info, check Keycloak documentation.

## Logger

Uses `log4js`. Overwrites global `console`. It's enabled by default.

```
console.log(message)
console.error(message)
console.info(message)
console.debug(message)
console.custom(type, level, message)
```

It can be configured through the `log4js.json` file at project's root level. More info: [https://log4js-node.github.io/log4js-node/index.html](https://log4js-node.github.io/log4js-node/index.html)


## Translations

Translations use `json` files in `/i18n`. This files will store keys and values of the translations. The files must be named as follows, where XX is the lang code: `lang_[XX].json`.  

The system has the **DEFAULT_LANG**, which states the default language of the backend instance and allows loading any language in the `ì18n` folder of the project.

- `App.i18n.load(XX)` loads a language.
- `App.i18n.translate(key, [lang])` translates key. Uses the default language if the lang param is not sent.


## Events

The app has a cluster safe event handler system.

To setup the events listener:
 ``` javascript
import { App } from '@landra_sistemas/lisco'

App.events.on('custom', function foo(props) {
    console.log(props);
})
 ```

This will make the app to listen to 'custom' events and it will print the event props.

To emit an event:

 ``` javascript
import { App } from '@landra_sistemas/lisco'

App.events.emit('custom', { test: "test" })
 ```

 This will emit an event with props: `{ test: "test" }`.

## Filters

`KnexFilterParser` converts objects into filters. 
     
- Standard filter:
``` json
"filters": {
    "column": "value" // generic 'exact' filter
}
```
- Oject filter:
``` json
"filters": {
    "column": {
        "type": "date|between|exists|notexists|greater|greaterEq|less|lessEq|exact|exactI|not|null|notnull|like|likeI",
        "start": "xxx", //start range of date and between type filters
        "end": "xxx", //end range of date and between type filters
        "value": "xxx" //value for filters others than date and between
    }
}
```
- List filter:
``` json
"filters": {
    "column": [1, 2, 3]
}
// IN type filer for all the matching elements
```

      
- Types definition:
    - **fql**: FQL type filter (https://github.com/landra-sistemas/fql_parser)
    - **date**: date range filter
    - **between**: filter between to values
    - **full-text-psql**: fuzzy query for any column of a table, only for PostgreSQL (`to_tsvector(${prop}::text) @@ to_tsquery(?)`)
    - **exists**: checks if a value exists
    - **notexists**: checks if a value not exists
    - **greater**: greater than
    - **greaterEq**: greater or equal than
    - **less**: lesser than
    - **lessEq**: lesser or equal than
    - **exact**: exact value
    - **not**: different than
    - **null**: equal to null
    - **notnull**: not null
    - **like**: like filter
    - **likeI**: case insensitive like

> All the filers, except exists, notexists, fql and full-text-psql, have a 'raw' option (dateraw, betweenraw) which allows to use column custom SQL sintax. It's used, for example, with PostgreSQL to run JSON type queries (`column->>'test'`).

### Sorting

In order to sort required data, it's needed to add the following object in the payload of the request:

```
{
    ...
    "filters": {...},
    "sort": {
        "field": "column name",
        "direction": "ascend|descend"
    }
}
```

 ## Server Views

 The `express` framework allows the use of any server side rendering, supported by it. More info: https://expressjs.com/en/resources/template-engines.html and https://expressjs.com/en/guide/using-template-engines.html

 Example with handlebars:
``` bash
> npm install express-handlebars
```
>

Once the dependency is installed, initialize the middleware as follows:

**index.js**
``` javascript
import { create } from "express-handlebars";


module.exports = async () => {
    [...]

    App.customizeExpress = (app) => {
        const hbs = create({
            // This helpers may be functions called from the views to render content.
            helpers: {
                foo() {
                    return "FOO!";
                },
                bar() {
                    return "BAR!";
                },
            },
        });
        app.engine("handlebars", hbs.engine);
        app.set("view engine", "handlebars");
        app.set("views", "./views");
    };

    [...]
};
```

Add the folder `views` to the root content and add the needed views:

**views/home.handlebars**
``` handlebars
<h1>Example App: Home</h1>
```

**views/layouts/main.handlebars**
``` handlebars
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <title>Example App</title>
    </head>
    <body>
        {{#if showTitle}}
        <h1>Home</h1>
        {{/if}}

        {{{body}}}


        <!-- Calls `foo` helper, overridden at render-level. -->
        <p>{{foo}}</p>

        <!-- Calls `bar` helper, defined at instance-level. -->
        <p>{{bar}}</p>

    </body>
</html>
```
Controllers must be created to serve the different views.

**controllers/HomeController.js**
``` javascript
import { BaseController, Utils } from "@landra_sistemas/lisco";

export default class HomeController extends BaseController {
    configure() {
        const exAsync = Utils.expressHandler();
        this.router.get( "/", exAsync((...args) => this.home(...args)));
        
        return this.router;
    }

    home(req, res) {
        res.render("home", {
            showTitle: true,

            // Helpers can be overriden from here:
            helpers: {
                foo() {
                    return "foo.";
                },
            },
        });
    }
}
```

Then, add the controller to the routes array:
**index.js**
``` javascript
App.routes = [
    ...
    new HomeController(),
    ...
];
```

## Runtime CLI

Lisco runtime adds CLI params (not enabled by default). Enable with `App.runtime();`.

``` javascript
//module.exports = async () => {
    App.runtime();

    [...]
//};
```
> It's recommended to start the runtime as the first call in the `index` file.

Once it's running, it will accept the following params, via terminal:

- -h o --help: shows help with the available params
- --generateKeys: generates the app's encryption keys
- --encrypt string: encrypts a string passed as an argument.

### Optional features

This method can receive as params a list of additional elements to extend the runtimes functionalities. It has to have the following structure;

``` javascript
[
    {
        "key": "c", //param name abbreviation (-c)
        "alias": "config", //alias (--config)
        "describe": "Configuration", //description
        "fn": function(argv) { }, //function called
        "nargs": 0, //number of arguments
        "required": false, //mandatory or not
        "boolean": false, //states if a field is a boolean (true, false)
        "choices": ["foo", "bar"], //possible cli options
    }   
]
```	
> In order to use async functions, an await must be implemented at the runtime init (`await App.runtime(extra);`)

## Server Monitoring

Adapted from: https://github.com/RafalWilinski/express-status-monitor. CDN's implementation limits the projects deploy, but it's useful to be included as a monitoring tool: https://github.com/thorin8k/express-status-monitor.

To install the fork:

``` bash
> npm install https://github.com/thorin8k/express-status-monitor
``` 

Once installed, it must be included in the `customizeExpress` method:

``` javascript
App.customizeExpress = (app) => { 
    //Monitoring
    app.use(
        require("express-status-monitor")({
            title: "Server Backend",
            path: '/status',
            websocket: App.io //Lisco inits a socketio by, if disabled (socketio: false), remove this line
        })
    );
};
``` 

More info: https://github.com/thorin8k/express-status-monitor

> Lisco starts `socketio` by default in the next port number from the configured one. If socketio is disabled, it's needed to remove the `socketio` line, `so the monitor will start it's own server.

## SocketIO

WIP 
``` javascript
 App.ioevents = {
        connection: (socket) => {
            console.log(`⚡: "${socket.id}" user just connected!`);
            socket.on("disconnect", () => {
                console.log(`⚡: "${socket.id}" user just disconnected!`);
            });
        },
    };
```
