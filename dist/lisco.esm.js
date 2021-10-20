'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var helmet = require('helmet');
var express = require('express');
var compression = require('compression');
var cors = require('cors');
var fileUpload = require('express-fileupload');
var url = require('url');
var lodash = require('lodash');
var fs = require('fs');
var path = require('path');
var util = require('util');
var crypto = require('crypto');
var jsonwebtoken = require('jsonwebtoken');
var uuid = require('uuid');
var http = require('http');
var https = require('https');
var cluster = require('cluster');
var socketio = require('socket.io');
var os = require('os');
var events = require('events');
var log4js = require('log4js');
var expressAsyncHandler = require('express-async-handler');
var pathToRegexp = require('path-to-regexp');
var moment = require('moment');
var net = require('net');
var repl = require('repl');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

function _interopNamespace(e) {
    if (e && e.__esModule) return e;
    var n = Object.create(null);
    if (e) {
        Object.keys(e).forEach(function (k) {
            if (k !== 'default') {
                var d = Object.getOwnPropertyDescriptor(e, k);
                Object.defineProperty(n, k, d.get ? d : {
                    enumerable: true,
                    get: function () {
                        return e[k];
                    }
                });
            }
        });
    }
    n['default'] = e;
    return Object.freeze(n);
}

var helmet__default = /*#__PURE__*/_interopDefaultLegacy(helmet);
var express__default = /*#__PURE__*/_interopDefaultLegacy(express);
var compression__default = /*#__PURE__*/_interopDefaultLegacy(compression);
var cors__default = /*#__PURE__*/_interopDefaultLegacy(cors);
var fileUpload__default = /*#__PURE__*/_interopDefaultLegacy(fileUpload);
var url__default = /*#__PURE__*/_interopDefaultLegacy(url);
var lodash__default = /*#__PURE__*/_interopDefaultLegacy(lodash);
var fs__default = /*#__PURE__*/_interopDefaultLegacy(fs);
var path__default = /*#__PURE__*/_interopDefaultLegacy(path);
var util__default = /*#__PURE__*/_interopDefaultLegacy(util);
var crypto__default = /*#__PURE__*/_interopDefaultLegacy(crypto);
var jsonwebtoken__default = /*#__PURE__*/_interopDefaultLegacy(jsonwebtoken);
var uuid__namespace = /*#__PURE__*/_interopNamespace(uuid);
var http__default = /*#__PURE__*/_interopDefaultLegacy(http);
var https__default = /*#__PURE__*/_interopDefaultLegacy(https);
var cluster__default = /*#__PURE__*/_interopDefaultLegacy(cluster);
var socketio__default = /*#__PURE__*/_interopDefaultLegacy(socketio);
var os__default = /*#__PURE__*/_interopDefaultLegacy(os);
var expressAsyncHandler__default = /*#__PURE__*/_interopDefaultLegacy(expressAsyncHandler);
var moment__default = /*#__PURE__*/_interopDefaultLegacy(moment);
var net__default = /*#__PURE__*/_interopDefaultLegacy(net);
var repl__default = /*#__PURE__*/_interopDefaultLegacy(repl);

class Utils {
    static arrayToLower(mcArray) {
        let tmp = mcArray.join('~').toLowerCase();
        return tmp.split('~');
    }

    static replaceAll(str, find, replace) {
        return str.replace(new RegExp(find.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&'), 'g'), replace);
    }

    /**
     * Metodo de encript para las contraseñas y demas.
     * 
     * @param {*} text 
     */
    static encrypt(text) {
        const algorithm = 'aes-256-cbc';
        const secret = Buffer.from(process.env.CRYPT_SECRET, 'hex');
        const iv = Buffer.from(process.env.CRYPT_IV, 'hex');

        const cipher = crypto__default['default'].createCipheriv(algorithm, secret, iv);
        let encrypted = cipher.update(text);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return encrypted.toString('hex');
    }

    /**
     * Metodo de decrypt para las contraseñas y demas
     * @param {*} text 
     */
    static decrypt(text) {
        const algorithm = 'aes-256-cbc';
        const secret = Buffer.from(process.env.CRYPT_SECRET, 'hex');
        const iv = Buffer.from(process.env.CRYPT_IV, 'hex');

        const encryptedText = Buffer.from(text, 'hex');

        const decipher = crypto__default['default'].createDecipheriv(algorithm, secret, iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    }


    /**
     * 
     * Utiliza una promise para ejecutar un setTimeout y hacer un falso sleep.
     * 
     * @param {*} ms 
     */
    static sleep(ms) {
        let promise_sleep = util__default['default'].promisify(setTimeout);

        return promise_sleep(ms);
    }

    /**
     * 
     */
    static generateKeys() {
        return {
            key: crypto__default['default'].randomBytes(32).toString('hex'),
            iv: crypto__default['default'].randomBytes(16).toString('hex')
        }
    }



    static flattenObject(ob) {
        let toReturn = {};
        let flatObject;
        for (let i in ob) {
            if (!ob.hasOwnProperty(i)) {
                continue;
            }
            //Devolver los arrays tal cual
            if (ob[i] && Array === ob[i].constructor) {
                toReturn[i] = ob[i];
                continue;
            }
            if ((typeof ob[i]) === 'object') {
                flatObject = Utils.flattenObject(ob[i]);
                for (let x in flatObject) {
                    if (!flatObject.hasOwnProperty(x)) {
                        continue;
                    }
                    //Exclude arrays from the final result
                    if (flatObject[x] && Array === flatObject.constructor) {
                        continue;
                    }
                    toReturn[i + (!!isNaN(x) ? '.' + x : '')] = flatObject[x];
                }
            } else {
                toReturn[i] = ob[i];
            }
        }
        return toReturn;
    }

    static unflatten(data) {
        var result = {};
        for (var i in data) {
            var keys = i.split('.');
            keys.reduce(function (r, e, j) {
                return r[e] || (r[e] = isNaN(Number(keys[j + 1])) ? (keys.length - 1 == j ? data[i] : {}) : [])
            }, result);
        }
        return result
    }

}

class I18nLoader {

    /**
     *
     * @param lang
     * @param callback
     */
    async load(custom) {
        const readfile = util__default['default'].promisify(fs__default['default'].readFile);
        const lang = custom || process.env.DEFAULT_LANG;

        if (!this.currentData) {
            this.currentData = {};
        }
        if (!this.currentDataRaw) {
            this.currentDataRaw = {};
        }
        //TODO mejorar el sistema cargando todas las traducciones del directorio i18n con chokidar esperando modificaciones

        let file = path__default['default'].resolve(process.cwd(), "i18n/lang_" + lang + ".json");
        try {
            const data = await readfile(file, 'utf8');
            var parsedData = JSON.parse(data);

            this.currentData[lang] = Utils.flattenObject(parsedData);
            this.currentDataRaw[lang] = parsedData;
        } catch (ex) {
            console.log("Lang file does not exist. Create it on ./i18n/lang_{xx}.json");
        }
    }

    /**
     * 
     * @param {*} key 
     */
    async translate(key, lang) {
        if (!lang) lang = process.env.DEFAULT_LANG;

        if (this.currentData && this.currentData[lang] && this.currentData[lang][key]) {
            return this.currentData[lang][key]
        }

        if (!this.currentData || !this.currentData[lang]) {
            await this.load(lang);
            if (this.currentData && this.currentData[lang] && this.currentData[key]) {
                return this.currentData[lang][key]
            }
        }
        return "undefined." + key;
    }
}

class JsonResponse {
    constructor(success, data, message, total) {
        this.data = data;
        this.success = success;
        this.total = total;
        this.message = message || '';
    }

    toJson() {
        return (this);
    }
}

/**
 * Example to refresh tokens using https://github.com/auth0/node-jsonwebtoken
 * It was requested to be introduced at as part of the jsonwebtoken library,
 * since we feel it does not add too much value but it will add code to mantain
 * we won't include it.
 *
 * I create this gist just to help those who want to auto-refresh JWTs.
 */

class TokenGenerator {

    constructor(privateKey, options) {
        this.privateKey = privateKey;
        this.options = options;
    }

    sign(payload) {
        const jwtSignOptions = { ...this.options, jwtid: uuid__namespace.v4() };
        return jsonwebtoken__default['default'].sign(payload, this.privateKey, jwtSignOptions);
    }

    verify(token) {
        return jsonwebtoken__default['default'].verify(token, this.privateKey, this.options);
    }

    refresh(token) {
        const payload = jsonwebtoken__default['default'].verify(token, this.privateKey, this.options);
        delete payload.sub;
        delete payload.iss;
        delete payload.aud;
        delete payload.iat;
        delete payload.exp;
        delete payload.nbf;
        delete payload.jti; //We are generating a new token, if you are using jwtid during signing, pass it in refreshOptions
        const jwtSignOptions = { ...this.options, jwtid: uuid__namespace.v4() };
        // The first signing converted all needed options into claims, they are already in the payload
        return jsonwebtoken__default['default'].sign(payload, this.privateKey, jwtSignOptions);
    }
}

/**
 * Clase servidor encargada de configurar las rutas.
 *
 * que el codigo se disperse entre diferentes proyectos.
 */
class Server {

    constructor(config, statics, routes) {
        this.app = express__default['default']();
        this.express_config = lodash__default['default'].defaultsDeep(config, {
            helmet: true,
            json: true,
            urlencoded: true,
            compression: true,
            cors: { origin: true, credentials: true },
            fileupload: true
        });
        this.statics = statics;
        this.routes = routes;
    }


    /**
     * Inicializa el servidor
     * @param {*} statics 
     * @param {*} routes 
     */
    async initialize() {
        this.config(this.express_config);
        if (this.customizeExpress) {
            await this.customizeExpress(this.app);
        }
        this.configureRoutes(this.routes);
        this.errorHandler();
    }

    /**
     * Funcion sobreescribible para personalizar los componentes cargados en Express
     * 
     * Aqui se pueden poner cosas como:
     * 
     * this.app.use(cookieParser())... etc
     */
    customizeExpress() { }

    /**
     * Se encarga de realizar la configuración inicial del servidor
     * 
     */
    config(config) {

        if (config && config.helmet) {
            //Security
            this.app.use(helmet__default['default'](config && lodash__default['default'].isObject(config.helmet) && config.helmet));
        }
        if (config && config.json) {
            //mount json form parser
            this.app.use(express__default['default'].json());
        }

        if (config && config.urlencoded) {
            //mount query string parser
            this.app.use(express__default['default'].urlencoded({ extended: true }));
        }
        if (config && config.compression) {
            // compress responses
            this.app.use(compression__default['default']());
        }
        if (config && config.cors) {
            //Enable cors to allow external references
            this.app.options('*', cors__default['default'](config && lodash__default['default'].isObject(config.cors) && config.cors));
            this.app.use(cors__default['default'](config && lodash__default['default'].isObject(config.cors) && config.cors));
        }
        if (config && config.fileupload) {
            // upload middleware
            this.app.use(fileUpload__default['default']());
        }

        if (this.statics) {
            //add static paths
            for (const idx in this.statics) {
                this.app.use(idx, express__default['default'].static(this.statics[idx]));
            }
        }

        //Logging
        if (!process.env.DISABLE_LOGGER) {
            this.app.use((request, response, next) => {
                request.requestTime = Date.now();
                response.on("finish", () => {
                    let pathname = url__default['default'].parse(request.url).pathname;
                    let end = Date.now() - request.requestTime;
                    let user = (request && request.session && request.session.user_id) || "";

                    console.debug('APIRequest[' + process.pid + ']::. [' + request.method + '] (user:' + user + ')  ' + pathname + ' |-> took: ' + end + ' ms');
                    console.debug(JSON.stringify(request.body));
                });
                next();
            });
        }
    }

    /**
     * Crea el cargador automatico de rutas
     */
    configureRoutes(routes) {
        const router = express__default['default'].Router();
        this.app.use(router);

        //create controllers
        this.loadRoutes(this.app, routes);
    }

    /**
     * Instancia la lista de rutas disponibles
     * @param apps
     * @returns {*}
     */
    loadRoutes(app, routes) {
        if (!routes) return;

        for (const route of routes) {
            if (!route) continue;
            //TODO -> FIXME traze if null?
            const router = route.configure();
            if (router) {
                app.use(router);
            }
        }
    }

    /**
     * Errores
     */
    errorHandler() {
        // error handler
        this.app.use((err, req, res, next) => {
            let jsRes = new JsonResponse();
            jsRes.success = false;
            jsRes.message = err.message;
            console.error(err);

            res.status(500).json(jsRes.toJson());
        });
    }
}

/**
 * Inicializa la escucha del server en modo cluster
 */
class ClusterServer extends events.EventEmitter {
    constructor(app) {
        super();

        if (!process.env.PORT) {
            console.log('Using 3000 as default port. Customize via env PORT.');
        }
        this.port = this.normalizePort(process.env.PORT || 3000);
        this.clustered = process.env.CLUSTERED;
        this.workers = [];
        this.app = app;

        this.executeOnlyMain = () => { };
    }

    setServerCls(cls) {
        this.cls = cls;
    }


    /**
     * Iniciar el servidor en el puerto y con la configuración seleccionadas.
     */
    async start() {
        if (this.clustered == "true") {
            this.initClustered();
        } else {

            this.executeOnlyMain();
            await this.initUnclustered();
        }
    }

    /**
     * Inicializa la clase server encargada del control de las solicitudes en forma multiproceso.
     *
     */
    async initClustered() {
        //Launch cluster
        if (cluster__default['default'].isMaster) {
            this.executeOnlyMain();
            //Count the machine's CPUs
            const cpuCount = os__default['default'].cpus().length;

            //Create a worker for each CPU
            for (let idx = 0; idx < cpuCount; idx += 1) {
                this.initWorker();
            }

            //Listen for dying workers
            cluster__default['default'].on('exit', (worker) => {

                //Replace the dead worker, we're not sentimental
                console.log('Worker ' + worker.id + ' died :(');
                this.initWorker();

            });
        } else {
            await this.initUnclustered();

            console.log(`Worker ${process.pid} started`);
        }
    }
    /**
     * Inicia un worker
     */
    initWorker() {
        let worker = cluster__default['default'].fork();
        console.log(`Running worker ${worker.process.pid}`);
        worker.on('message', (msg) => {
            if (msg.event) {
                console.debug(`Received ${msg.event} on ${worker.process.pid}`);
                for (var i in this.workers) { //Si se recibe un mensaje de un worker implica que alguno de ellos ha desencadenado un evento.
                    //Se notifica a todos los demas workers
                    var current = this.workers[i];
                    current.send(msg);
                    console.log("Sending to workers");
                }
                //Desencadenar en el proceso principal tambien
                this.app.events.emit(msg.event, msg.props);
            }
        });
        this.workers.push(worker);
    }
    /**
     * Inicializa la clase server encargada del control de las solicitudes en un unico proceso.
     *
     */
    async initUnclustered() {
        //Initialize clustered servers
        this.server = this.cls;

        this.server.port = this.port;
        //create http server
        let server = http__default['default'].Server(this.server.app);

        this.app.io = socketio__default['default'](server);

        await this.server.initialize();

        if (this.server.beforeListen) await this.server.beforeListen();
        //listen on provided ports
        server.listen(this.server.port);

        if (this.server.afterListen) await this.server.afterListen();

        //add error handler
        server.on("error", (err) => {
            this.handleErrors(err, this.server.port);
        });
        //start listening on port
        server.on("listening", () => {
            console.log('Server Worker running on port: ' + this.port + '!');
            this.emit('listening', this.port);
        });

        if (process.env.SSL && process.env.SSL == "true") {
            if (!process.env.SSL_KEY || !process.env.SSL_CERT || !process.env.SSL_PASS) {
                console.error('Invalid SSL configuration. SLL_KEY, SSL_CERT and SSL_PASS needed');
                process.exit(0);
            }

            var key = fs__default['default'].readFileSync(path__default['default'].resolve(process.cwd(), process.env.SSL_KEY || 'key.pem'));
            var cert = fs__default['default'].readFileSync(path__default['default'].resolve(process.cwd(), process.env.SSL_CERT || 'cert.pem'));

            var options = {
                key: key,
                cert: cert,
                passphrase: process.env.SSL_PASS,
            };

            if (!process.env.SSL_PORT) {
                console.log('Using 3443 as ssl default port. Customize via env SSL_PORT.');
            }
            var sslPort = this.normalizePort(process.env.SSL_PORT || 3443);
            var serverSsl = https__default['default'].createServer(options, this.server.app);
            serverSsl.listen(sslPort);
            //add error handler
            serverSsl.on("error", function (err) {
                self.handleErrors(err, sslPort);
            });
            //start listening on port
            serverSsl.on("listening", function () {
                console.log('Server Worker running on port: ' + sslPort + '!');
                this.emit('listening_ssl', sslPort);
            });
        }
    }

    /**
     * Controla los posibles errores de formato en el puerto
     * @param val
     * @returns {*}
     */
    normalizePort(val) {
        let port = parseInt(val, 10);

        if (isNaN(port)) {
            //named pipe
            return val;
        }

        if (port >= 0) {
            //port number
            return port;
        }

        return false;
    }
    /**
     * Gestiona los errores en el listen del servidor
     */
    handleErrors(error, port) {
        if (error.syscall !== "listen") {
            throw error;
        }

        let bind = typeof port === "string"
            ? "Pipe " + port
            : "Port " + port;

        //handle specific listen errors with friendly messages
        switch (error.code) {
            case "EACCES":
                console.error(bind + " requires elevated privileges");
                process.exit(1);
                break;
            case "EADDRINUSE":
                console.error(bind + " is already in use");
                process.exit(1);
                break;
            default:
                throw error;
        }
    }
}

/**
 * Clase encargada de la generacion de eventos.
 */
class EventHandler extends events.EventEmitter {

    constructor(app) {
        super();

        this.app = app; //Se recibe el singleton App para evitar referencias cruzadas

        if (cluster__default['default'].isWorker) {
            // Levanto, en los worker, la escucha para recibir los eventos en broadcast de los demas hilos
            process.on('message', (msg) => {
                console.debug(`Receiving broadcast ${msg.event} - ${process.pid}`);
                super.emit(msg.event, msg.props);
            });
        }
    }

    /**
     * Sobreescribir el emitter para notificar a los hijos
     * 
     * @param {*} evt 
     * @param {*} props 
     */
    emit(evt, props) {
        //Desencadenar en local
        super.emit(evt, props);

        if (evt && props && cluster__default['default'].isWorker) {
            console.debug(`${evt} -> Firing from ${process.pid} to master`);
            if (!props) {
                props = {};
            }
            props.owner = process.pid;
            process.send({ event: evt, props });
        }

        if (evt && props && cluster__default['default'].isMaster && this.app && this.app.server && this.app.server.workers) {
            console.debug(`${evt} -> Firing from master to workers`);
            for (var i in this.app.server.workers) { //Si se recibe un evento del master
                //Se notifica a todos los demas workers excepto al que lo ha generado
                var current = this.app.server.workers[i];
                if (props && current.process.pid !== props.owner) {
                    console.debug(`${evt} -> Sending to ${current.process.pid}`);
                    current.send({ event: evt, props });
                }
            }
        }
    }
}

/**
 * 
 */
class Logger {

    static async configure() {
        const readfile = util__default['default'].promisify(fs__default['default'].readFile);

        const json = await readfile(path__default['default'].resolve(process.cwd(), './log4js.json'), 'utf8');

        log4js.configure(JSON.parse(json));


        //Nota para el futuro:
        // Esto sobreescribe los metodos de console.log
        // Es necesario que la sitaxis se mantenga tal cual....
        (() => {

            const log_logger = log4js.getLogger('log');
            const error_logger = log4js.getLogger('error');
            const debug_logger = log4js.getLogger('debug');
            console.log = function () {
                let args = Array.prototype.slice.call(arguments);
                // log.apply(this, args);
                log_logger.log('info', args[0]);
            };
            console.error = function () {
                let args = Array.prototype.slice.call(arguments);
                // error.apply(this, args);
                error_logger.log('error', args[0]);
            };
            console.info = function () {
                let args = Array.prototype.slice.call(arguments);
                // info.apply(this, args);
                log_logger.log('info', args[0]);
            };
            console.debug = function () {
                /*if (global.settings.debug.value) {*/
                let args = Array.prototype.slice.call(arguments);
                // debug.apply(this, [args[1], args[2]]);
                debug_logger.log('debug', args[0]);
            };

            console.custom = function (logger, message) {
                const custom_logger = log4js.getLogger(logger);
                custom_logger.log(logger, message);
            };

        })();
    }

}

class AuthController {

    constructor(publicPathsList, AuthHandler) {
        this.router = express__default['default'].Router();
        this.publicPathsList = [...publicPathsList, '/login'];

        this.AuthHandler = AuthHandler;
    }


    configure() {
        this.router.use(expressAsyncHandler__default['default']((res, req, next) => { this.check(res, req, next); }));
        this.router.post('/login', expressAsyncHandler__default['default']((res, req, next) => { this.loginPost(res, req, next); }));
        this.router.post('/logout', expressAsyncHandler__default['default']((res, req, next) => { this.logout(res, req, next); }));

        return this.router;
    }

    /**
     * Controla que los usuarios tengan sesion para acceder a los metodos privados de la API
     * 
     * @param {*} request 
     * @param {*} response 
     * @param {*} next 
     */
    async check(request, response, next) {
        try {
            //Rutas ublicas 
            for (let path of this.publicPathsList) {
                const expr = pathToRegexp.pathToRegexp(path);
                if (expr.exec(url__default['default'].parse(request.url).pathname) !== null) {
                    return next();
                }
            }

            if (await this.AuthHandler.check(request)) {
                return next()
            }

            return response.status(403).json(new JsonResponse(false, null, 'Forbidden').toJson());
        } catch (ex) {
            console.error(ex);
            return response.status(403).json(new JsonResponse(false, null, 'Forbidden').toJson());
        }
    }


    /**
     * Valida los credenciales de un usuario
     * 
     * TODO logger console.custom("access", INFO);
     * 
     * @param {*} request 
     * @param {*} response 
     */
    async loginPost(request, response) {
        if (request.body.username) {
            try {
                let data = await this.AuthHandler.validate(request, request.body.username, request.body.password);
                if (data) {
                    return response.status(200).json(new JsonResponse(true, data).toJson());
                }
                return response.status(401).json(new JsonResponse(false, null, 'Unauthorized - Incorrect credentials').toJson());
            } catch (ex) {
                console.error(ex);
                return response.status(401).json(new JsonResponse(false, null, "Unauthorized - Error, check log").toJson());
            }
        }
        return response.status(401).json(new JsonResponse(false, null, "Unauthorized - Missing parameters").toJson());
    }

    /**
     * Cierra la sesion del usuario
     * 
     * @param {*} request 
     * @param {*} response 
     */
    async logout(request, response) {
        if (this.AuthHandler.logout) { //Depende de que el authHandler implementado pueda realizar esta accion
            try {
                await this.AuthHandler.logout(request);
                return response.status(200).json(new JsonResponse(true).toJson());
            } catch (ex) {
                console.error(ex);
                return response.status(500).json(new JsonResponse(false, null, ex).toJson());
            }
        }
        return response.status(200).json(new JsonResponse(true).toJson());
    }


}

class IAuthHandler {
    constructor() {
        if (!this.check) {
            throw new Error("AuthHandler must have 'check' vethod");
        }
        if (!this.validate) {
            throw new Error("AuthHandler must have 'validate' vethod");
        }
        // logout method is optional
    }
}

class JwtAuthHandler extends IAuthHandler {
    constructor(UserDao) {
        super();

        this.tokenGenerator = new TokenGenerator(process.env.JWT_SECRET, { audience: process.env.JWT_AUDIENCE, issuer: process.env.JWT_ISSUER, subject: process.env.JWT_SUBJECT, algorithm: process.env.JWT_ALGORITHM, expiresIn: process.env.JWT_EXPIRES });

        if (!UserDao) {
            throw new Error("Need 'UserDao' for user validation. Create 'UserDao' class extending 'IUserDao'");
        }
        this.userDao = UserDao;
    }

    /**
     * Metodo encargado de realizar la comprobacion para validar si la sesion del usuario es válida
     * 
     * @param {*} request 
     */
    async check(request) {
        if (request.headers.authorization) {
            const token = (request.headers.authorization || '').split(' ')[1] || '';

            if (!token) {
                console.error("Token needed");
                return false;
            }
            
            var decoded = this.tokenGenerator.verify(token);
            const { sub, username, exp } = decoded;

            if (!sub || !username || moment__default['default'](exp).isAfter(new Date())) {
                return false;
            }

            //Si la sesion es valida, lo introducimos en el contexto de la solicitud
            request.session = { ...request.session, ...decoded };
            return true;
        }
        return false;
    }

    /**
     * Método encargado de realizar la validación de un usuario. Utiliza IUserDao como interfaz para la realización de la query a BD.
     * 
     * @param {*} username 
     * @param {*} password 
     */
    async validate(request, username, password) {

        const user = await this.userDao.findByUsername(username);

        if (user && user.username === username && user.password === Utils.encrypt(password)) {
            return this.tokenGenerator.sign(lodash__default['default'].omit(user, ['password']));
        }

        return false;
    }

}

/**
 * Necesario:
 *  Instalar -->   express-session y algun session store
 * 
 *  Mas info: https://www.npmjs.com/package/express-session
 * 
 *  App.customizeExpress = () => {
       this.app.use(session({
            secret: 'keyboard cat',
            resave: false,
            saveUninitialized: true,
            cookie: { secure: true }
        }));
    }
 */

class CookieAuthHandler extends IAuthHandler {
    constructor(UserDao) {
        super();

        if (!UserDao) {
            throw new Error("Need 'UserDao' for user validation. Create 'UserDao' class extending 'IUserDao'");
        }
        this.userDao = UserDao;
    }

    /**
     * Metodo encargado de realizar la comprobacion para validar si la sesion del usuario es válida
     * 
     * @param {*} request 
     */
    async check(request) {
        if (request.headers.authorization) { //Si se recibe por Auth Basic
            const token = (request.headers.authorization || '').split(' ')[1] || '';

            const creds = Buffer.from(token, 'base64').toString().split(':');
            const login = creds[0];
            const password = creds[1];

            if (!await this.validate(request, login, password)) {
                return false;
            }
            return true;
        }
        if (request.session && request.session.username) {//Si hay sesion almacenada
            return true;
        }
        return false;
    }

    /**
     * Método encargado de realizar la validación de un usuario. Utiliza IUserDao como interfaz para la realización de la query a BD.
     * 
     * @param {*} username 
     * @param {*} password 
     */
    async validate(request, username, password) {

        const user = await this.userDao.findByUsername(username);

        //TODO quizas poder configurar los nombres de username y password

        if (user && user.username === username && user.password === Utils.encrypt(password)) {
            request.session = { ...request.session, ...lodash__default['default'].omit(user, ['password']) };

            return true;
        }
        return false;
    }


    /**
     * 
     * @param {*} request 
     */
    logout(request) {
        return new Promise((resolve) => {
            if (request.session) {
                request.session.destroy(resolve);
            }
        })
    }

}

class KnexFilterParser {


    /**
     * Convierte un objeto clave valor en un conjunto de filtros.
     *
     * - Filtro estandar:
     *    filters: {
     *       "column": "value" -> filtro generico exact
     *    }
     * - Filtro Objeto:
     *    filters:{
     *       "column": {
     *       "type": "date|between|exists|notexists|greater|greaterEq|less|lessEq|exact|exactI|not|null|notnull|like|likeI"
     *       "start": "xxx", //inicio de rango para el filtro de date y between
     *       "end": "xxx", //fin de rango para el filtro date y between
     *       "value": "xxx" //valor a utilizar para el resto de filtros
     *     }
     * }
     *  - Filtro Lista:
     *     filters: {
     *       "column": [1, 2, 3]
     *     }
     *    Filtro de tipo IN, todos los elementos que coincidan
     * 
     * - Definicion de tipos:
     *    date: filtro de fechas desde y hasta
     *    between: filtro entre dos valores concretos
     *    exists: busca si existe la propiedad
     *    notexists: busca si existe la propiedad
     *    greater: mayor que
     *    greaterEq: mayor o igual que
     *    less: menor que
     *    lessEq: menor o igual que
     *    exact: valor exacto
     *    exactI: valor exacto ignorando mayusculas y minusculas
     *    not: distinto de
     *    null: igual a null
     *    notnull: distinto de null
     *    like: filtro like
     *    likeI: filtro like ignorando mayusculas y minusculas
     */
    static parseFilters(builder, filter) {
        let query = builder;

        for (let prop in filter) {

            let elm = filter[prop];

            if (typeof elm === 'object') {

                switch (elm.type) {
                    case 'date':
                    case 'between':
                        if (elm.start && elm.end) {
                            query = query.whereBetween(prop, [elm.start, elm.end]);
                        }
                        if (elm.start && !elm.end) {
                            query = query.where(prop, '>=', elm.start);
                        }
                        if (!elm.start && elm.end) {
                            query = query.where(prop, '>=', elm.end);
                        }
                        break;
                    case 'greater':
                        query = query.where(prop, '>', elm.value);
                        break;
                    case 'greaterEq':
                        query = query.where(prop, '>=', elm.value);
                        break;
                    case 'less':
                        query = query.where(prop, '<', elm.value);
                        break;
                    case 'lessEq':
                        query = query.where(prop, '<=', elm.value);
                        break;
                    case 'exists':
                        query = query.whereExists(prop);
                        break;
                    case 'notexists':
                        query = query.whereNotExists(prop);
                        break;
                    case 'exact':
                        query = query.where(prop, elm.value);
                        break;
                    case 'exactI':
                        //!FIXME https://github.com/knex/knex/issues/233
                        query = query.where(prop, 'ILIKE', elm.value);
                        break;
                    case 'in':
                        if (!Array.isArray(elm.value)) {
                            query = query.whereIn(prop, elm.value.split(','));
                        } else {
                            query = query.whereIn(prop, elm.value);
                        }
                        break;
                    case 'not':
                        query = query.whereNot(prop, elm.value);
                        break;
                    case 'like':
                        let value_like = Utils.replaceAll(elm.value, '*', '%');
                        query = query.where(prop, 'LIKE', value_like);
                        break;
                    case 'likeI':
                        //!FIXME https://github.com/knex/knex/issues/233
                        let value_ilike = Utils.replaceAll(elm.value, '*', '%');
                        query = query.where(prop, 'ILIKE', value_ilike);
                        break;
                    case 'null':
                        query = query.whereNull(prop);
                        break;
                    case 'notnull':
                        query = query.whereNotNull(prop);
                        break;
                }
            } else {
                //Si el valor no es un objeto se devuelve
                query = query.where(prop, elm);
            }
        }
        return query;
    }

    /**
     * Conversion de un objeto {property: XX, direction: ASC|DESC - ascend|descend} a un ORDER BY
     * 
     * @param {*} sorts 
     */
    static parseSort(sort) {
        if (!sort.field || !sort.direction) {
            return "";
        }

        let direction = "ASC";
        if (sort.direction === 'descend') {
            direction = "DESC";
        }
        return { column: sort.field, order: direction };
    }

}

class KnexConnector {

    init(config) {
        this.connection = require('knex')(config);
    }


    test() {
        return this.connection.raw('select 1+1 as result');
    }
}


var KnexConnector$1 = new KnexConnector();

/**
 * Crear un dao con los métodos básicos
 */
class BaseKnexDao {

    tableName = "";

    constructor() {

    }


    loadAllData(start, limit) {
        return KnexConnector$1.connection.select('*').from(this.tableName).limit(limit || 10000).offset(start)
    }

    async loadFilteredData(filters, start, limit) {
        let sorts = [];
        if (filters.sort) {
            sorts = KnexFilterParser.parseSort(filters.sort);
        }

        return KnexConnector$1.connection.from(this.tableName).where((builder) => (
            KnexFilterParser.parseFilters(builder, lodash__default['default'].omit(filters, ['sort', 'start', 'limit']))
        )).orderBy(sorts).limit(limit).offset(start);

    }

    async countFilteredData(filters) {
        let data = await KnexConnector$1.connection.from(this.tableName).where((builder) => (
            KnexFilterParser.parseFilters(builder, lodash__default['default'].omit(filters, ['sort', 'start', 'limit']))
        )).count('id', { as: 'total' });

        return data && data[0].total;
    }

    async loadById(objectId) {
        return KnexConnector$1.connection.from(this.tableName).where('id', objectId);
    }

    save(object) {
        return KnexConnector$1.connection.from(this.tableName).insert(object);
    }
    update(objectId, newObject) {
        return KnexConnector$1.connection.from(this.tableName).where("id", objectId).update(newObject);
    }
    delete(objectId) {
        return KnexConnector$1.connection.from(this.tableName).where("id", objectId).delete()
    }
}

class IUserDao extends BaseKnexDao {
    constructor(tableName) {
        super(tableName);

        if (!this.findByUsername) {
            throw new Error("AuthHandler must have 'findByUsername' method");
        }
    }
}

const asyncHandler = require('express-async-handler');


class BaseController {


    constructor() {
        this.router = express__default['default'].Router();
    }

    configure(entity, config) {
        this.router.post(`/${entity}/list`, asyncHandler((res, req, next) => { this.listEntidad(res, req, next); }));
        this.router.get(`/${entity}/:id`, asyncHandler((res, req, next) => { this.getEntidad(res, req, next); }));
        this.router.post(`/${entity}`, asyncHandler((res, req, next) => { this.saveEntidad(res, req, next); }));
        this.router.put(`/${entity}/:id`, asyncHandler((res, req, next) => { this.updateEntidad(res, req, next); }));
        this.router.delete(`/${entity}/:id`, asyncHandler((res, req, next) => { this.deleteEntidad(res, req, next); }));

        this.service = config.service;

        return this.router;
    }

    /**
     * Lista entidades en la aplicacion, es posible enviarle parametros de filtrado.
     *
     * !FIXME Todavia no se ha definido la lista de parametros a utilizar para el filtrado.
     *
     * @api {post} /:entidad/list Listar entidades
     * @apiName Listar entidades
     * @apiGroup Comun
     * @apiPermission Auth Basic username:pwd
     * @apiParam {Number} id entidades unique ID.
     *
     * @apiSuccess {Boolean} success
     * @apiSuccess {Object[]} data  dataObject
     */
    async listEntidad(request, response, next) {
        try {
            let service = new this.service();
            let filters = request.body;

            let data = await service.list(filters, filters.start, filters.limit);
            let jsRes = new JsonResponse(true, data, null, data.total);

            response.json(jsRes.toJson());
        } catch (e) {
            next(e);
        }
    }
    /**
     *Obtiene un elemento concreto mediante su identificador
     *
     *
     * @api {get} /:entidad/:id Obtener entidad
     * @apiName Obtener entidad
     * @apiGroup Comun
     * @apiPermission Auth Basic username:pwd
     * @apiParam {Number} id entidades unique ID.
     *
     * @apiSuccess {Boolean} success
     * @apiSuccess {Object[]} data  dataObject
     */
    async getEntidad(request, response, next) {
        try {
            let service = new this.service();
            let data = await service.loadById(request.params.id);
            let jsRes = new JsonResponse(true, data);

            response.json(jsRes.toJson());

        } catch (e) {
            next(e);
        }
    }

    /**
     * Almacena un elemento en BD
     *
     *
     * @api {post} /:entidad/:id Crear entidad
     * @apiName Crear entidad
     * @apiGroup Comun
     * @apiPermission Auth Basic username:pwd
     * @apiParam {Number} id entidades unique ID.
     *
     * @apiSuccess {Boolean} success
     * @apiSuccess {Object[]} data  dataObject
     */
    async saveEntidad(request, response, next) {
        try {
            let service = new this.service();

            let data = await service.save(request.body);
            let jsRes = new JsonResponse(true, { id: request.body.id || data[0] });

            response.json(jsRes.toJson());

        } catch (e) {
            next(e);
        }
    }

    /**
     * Almacena un elemento en BD
     *
     *
     * @api {put} /:entidad/:id Actualizar entidad
     * @apiName Actualizar entidad
     * @apiGroup Comun
     * @apiPermission Auth Basic username:pwd
     * @apiParam {Number} id entidades unique ID.
     *
     * @apiSuccess {Boolean} success
     * @apiSuccess {Object[]} data  dataObject
     */
    async updateEntidad(request, response, next) {
        try {
            let service = new this.service();

            let data = await service.update(request.params.id, request.body);
            let jsRes = new JsonResponse(true, { id: request.body.id || data[0] });

            response.json(jsRes.toJson());

        } catch (e) {
            next(e);
        }
    }

    /**
     * Elimina un elemento correspondiente al identificador recibido
     *
     *
     * @api {delete} /:entidad/:id/delete Delete entidad
     * @apiName Eliminar entidad
     * @apiGroup Comun
    * @apiPermission Auth Basic username:pwd
     * @apiParam {Number} id entidades unique ID.
     *
     * @apiSuccess {Boolean} success
     * @apiSuccess {Object[]} data  dataObject
     */
    async deleteEntidad(request, response, next) {
        try {
            let service = new this.service();
            let data = await service.delete(request.params.id);
            let jsRes = new JsonResponse(true, data);

            response.json(jsRes.toJson());

        } catch (e) {
            next(e);
        }
    }

}

class BaseService {


    constructor(cls) {
        if (cls) {
            this.dao = new cls();
        } else {
            this.dao = new BaseKnexDao(); //El sistema por defecto utiliza knex, si se pasa un dao personalizado se puede sobreescribir este comportamiento
        }
    }
    /**
     * Obtencion de una lista de elementos.
     *
     * filters, es opcional. Si no se pasan se devuelve lo que hay ;
     */
    list(filters, start, limit) {
        //Pagination
        var start = start || 0;
        var limit = limit || 1000;//Default limit

        //TODO  count;

        if (filters && Object.keys(filters).length !== 0) {

            return this.dao.loadFilteredData(filters, start, limit);
        }
        return this.dao.loadAllData(start, limit);
    }

    /**
     * Obtencion de un elemento mediante su identificador
     */
    loadById(id) {
        return this.dao.loadById(id);
    }
    /**
     * Metodo de creacion.
     *
     * Si el identificador se pasa como undefined se creara un nuevo elemento,
     * sino se modifica el correspondiente.
     */
    save(data) {
        //Create
        return this.dao.save(data);
    }
    /**
     * Metodo de creacion.
     *
     * Si el identificador se pasa como undefined se creara un nuevo elemento,
     * sino se modifica el correspondiente.
     */
    update(id, data) {
        if (id) {
            //Update
            return this.dao.update(id, data);
        }
    }
    /**
     * Metodo de eliminado.
     *
     * El identificador es obligatorio para poder localizar el elemento a eliminar.
     */
    delete(id) {
        if (id) {
            return this.dao.delete(id);
        }
    }
}

class App {

    serverClass = Server
    clusterClass = ClusterServer

    /**
     * Initializa las configuraciones para la app
     * 
     */
    async init(serverConfig) {
        if (process.env.DISABLE_LOGGER != "true") {
            await Logger.configure();
        }

        //Instanciar la clase server
        const server = new this.serverClass(serverConfig, this.statics, this.routes);
        if (this.customizeExpress) {
            server.customizeExpress = this.customizeExpress;
        }
        if (this.beforeListen) {
            server.beforeListen = this.beforeListen;
        }
        if (this.afterListen) {
            server.afterListen = this.afterListen;
        }

        //Gestor de eventos
        this.events = new EventHandler(this);
        //Carga de utilidades
        this.i18n = new I18nLoader();
        await this.i18n.load();
        //Inicio del cluster server
        this.server = new this.clusterClass(this);

        this.server.setServerCls(server);
        this.server.executeOnlyMain = () => {
            if (this.executeOnlyMain) this.executeOnlyMain();

            if (process.env.REPL_ENABLED == "true") {
                this.startRepl();
            }
        };
    }

    /**
     * Ejecuta el servidor con la configuracion de #init()
     */
    async start() {
        if (!this.server) {
            throw new Error("Call init first");
        }
        await this.server.start();
    }


    /**
     * Inicia el server replify para poder conectar terminales remotas
     * 
     * 
     * Para que arranque es necesario especificar REPL_ENABLED en el archivo .env
     */
    startRepl() {
        try {
            net__default['default'].createServer((socket) => {
                const remote = repl__default['default'].start({
                    prompt: "lisco::remote> ",
                    input: socket,
                    output: socket,
                    terminal: true,
                    useColors: true,
                    preview: false
                });
                remote.context.app = this;
                remote.context.Utils = Utils;
                remote.on('exit', socket.end.bind(socket));
            }).listen(process.env.REPL_PORT || 5001);
        } catch (e) {
            console.log("Remote REPL Conn: " + e);
        }

        console.log(`Remote REPL started on port ${(process.env.REPL_PORT || 5001)}`);

    }
}

var App$1 = new App();

exports.App = App$1;
exports.AuthController = AuthController;
exports.BaseController = BaseController;
exports.BaseKnexDao = BaseKnexDao;
exports.BaseService = BaseService;
exports.ClusterServer = ClusterServer;
exports.CookieAuthHandler = CookieAuthHandler;
exports.EventHandler = EventHandler;
exports.I18nLoader = I18nLoader;
exports.IAuthHandler = IAuthHandler;
exports.IUserDao = IUserDao;
exports.JsonResponse = JsonResponse;
exports.JwtAuthHandler = JwtAuthHandler;
exports.KnexConnector = KnexConnector$1;
exports.KnexFilterParser = KnexFilterParser;
exports.Logger = Logger;
exports.Server = Server;
exports.TokenGenerator = TokenGenerator;
exports.Utils = Utils;
