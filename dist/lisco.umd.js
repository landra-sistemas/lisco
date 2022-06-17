(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('helmet'), require('express'), require('compression'), require('cors'), require('express-fileupload'), require('url'), require('lodash'), require('fs'), require('util'), require('crypto'), require('chokidar'), require('jsonwebtoken'), require('uuid'), require('http'), require('https'), require('path'), require('cluster'), require('socket.io'), require('os'), require('events'), require('cluster-messages'), require('log4js'), require('path-to-regexp'), require('moment'), require('@landra_sistemas/fql-parser'), require('knex'), require('net'), require('repl'), require('optimist')) :
  typeof define === 'function' && define.amd ? define(['exports', 'helmet', 'express', 'compression', 'cors', 'express-fileupload', 'url', 'lodash', 'fs', 'util', 'crypto', 'chokidar', 'jsonwebtoken', 'uuid', 'http', 'https', 'path', 'cluster', 'socket.io', 'os', 'events', 'cluster-messages', 'log4js', 'path-to-regexp', 'moment', '@landra_sistemas/fql-parser', 'knex', 'net', 'repl', 'optimist'], factory) :
  (global = global || self, factory(global.lisco = {}, global.helmet, global.express, global.compression, global.cors, global.expressFileupload, global.url, global.lodash, global.fs, global.util, global.crypto, global.chokidar, global.jsonwebtoken, global.uuid, global.http, global.https, global.path, global.cluster, global.socket_io, global.os, global.events, global.clusterMessages, global.log4Js, global.pathToRegexp, global.moment, global.fqlParser, global.knex, global.net, global.repl, global.optimist));
})(this, (function (exports, helmet, express, compression, cors, fileUpload, url, lodash, fs, util, crypto, chokidar, jsonwebtoken, uuid, http, https, path, cluster, socket_io, os, events, ClusterMessages, log4js, pathToRegexp, moment, fqlParser, Knex, net, repl, _optimist) {
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
            get: function () { return e[k]; }
          });
        }
      });
    }
    n["default"] = e;
    return n;
  }

  var helmet__default = /*#__PURE__*/_interopDefaultLegacy(helmet);
  var express__default = /*#__PURE__*/_interopDefaultLegacy(express);
  var compression__default = /*#__PURE__*/_interopDefaultLegacy(compression);
  var cors__default = /*#__PURE__*/_interopDefaultLegacy(cors);
  var fileUpload__default = /*#__PURE__*/_interopDefaultLegacy(fileUpload);
  var url__default = /*#__PURE__*/_interopDefaultLegacy(url);
  var lodash__default = /*#__PURE__*/_interopDefaultLegacy(lodash);
  var fs__default = /*#__PURE__*/_interopDefaultLegacy(fs);
  var util__default = /*#__PURE__*/_interopDefaultLegacy(util);
  var crypto__default = /*#__PURE__*/_interopDefaultLegacy(crypto);
  var chokidar__default = /*#__PURE__*/_interopDefaultLegacy(chokidar);
  var jsonwebtoken__default = /*#__PURE__*/_interopDefaultLegacy(jsonwebtoken);
  var uuid__namespace = /*#__PURE__*/_interopNamespace(uuid);
  var http__default = /*#__PURE__*/_interopDefaultLegacy(http);
  var https__default = /*#__PURE__*/_interopDefaultLegacy(https);
  var path__default = /*#__PURE__*/_interopDefaultLegacy(path);
  var cluster__default = /*#__PURE__*/_interopDefaultLegacy(cluster);
  var os__default = /*#__PURE__*/_interopDefaultLegacy(os);
  var ClusterMessages__default = /*#__PURE__*/_interopDefaultLegacy(ClusterMessages);
  var log4js__default = /*#__PURE__*/_interopDefaultLegacy(log4js);
  var moment__default = /*#__PURE__*/_interopDefaultLegacy(moment);
  var Knex__default = /*#__PURE__*/_interopDefaultLegacy(Knex);
  var net__default = /*#__PURE__*/_interopDefaultLegacy(net);
  var repl__default = /*#__PURE__*/_interopDefaultLegacy(repl);
  var _optimist__default = /*#__PURE__*/_interopDefaultLegacy(_optimist);

  function _extends() {
    _extends = Object.assign ? Object.assign.bind() : function (target) {
      for (var i = 1; i < arguments.length; i++) {
        var source = arguments[i];

        for (var key in source) {
          if (Object.prototype.hasOwnProperty.call(source, key)) {
            target[key] = source[key];
          }
        }
      }

      return target;
    };
    return _extends.apply(this, arguments);
  }

  function _inheritsLoose(subClass, superClass) {
    subClass.prototype = Object.create(superClass.prototype);
    subClass.prototype.constructor = subClass;

    _setPrototypeOf(subClass, superClass);
  }

  function _setPrototypeOf(o, p) {
    _setPrototypeOf = Object.setPrototypeOf ? Object.setPrototypeOf.bind() : function _setPrototypeOf(o, p) {
      o.__proto__ = p;
      return o;
    };
    return _setPrototypeOf(o, p);
  }

  function _assertThisInitialized(self) {
    if (self === void 0) {
      throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
    }

    return self;
  }

  function _unsupportedIterableToArray(o, minLen) {
    if (!o) return;
    if (typeof o === "string") return _arrayLikeToArray(o, minLen);
    var n = Object.prototype.toString.call(o).slice(8, -1);
    if (n === "Object" && o.constructor) n = o.constructor.name;
    if (n === "Map" || n === "Set") return Array.from(o);
    if (n === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return _arrayLikeToArray(o, minLen);
  }

  function _arrayLikeToArray(arr, len) {
    if (len == null || len > arr.length) len = arr.length;

    for (var i = 0, arr2 = new Array(len); i < len; i++) arr2[i] = arr[i];

    return arr2;
  }

  function _createForOfIteratorHelperLoose(o, allowArrayLike) {
    var it = typeof Symbol !== "undefined" && o[Symbol.iterator] || o["@@iterator"];
    if (it) return (it = it.call(o)).next.bind(it);

    if (Array.isArray(o) || (it = _unsupportedIterableToArray(o)) || allowArrayLike && o && typeof o.length === "number") {
      if (it) o = it;
      var i = 0;
      return function () {
        if (i >= o.length) return {
          done: true
        };
        return {
          done: false,
          value: o[i++]
        };
      };
    }

    throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.");
  }

  var Utils = /*#__PURE__*/function () {
    function Utils() {}

    Utils.arrayToLower = function arrayToLower(mcArray) {
      var tmp = mcArray.join('~').toLowerCase();
      return tmp.split('~');
    };

    Utils.replaceAll = function replaceAll(str, find, replace) {
      return str.replace(new RegExp(find.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&'), 'g'), replace);
    }
    /**
     * Metodo de encript para las contraseñas y demas.
     * 
     * @param {*} text 
     */
    ;

    Utils.encrypt = function encrypt(text) {
      var algorithm = 'aes-256-cbc';
      var secret = Buffer.from(process.env.CRYPT_SECRET, 'hex');
      var iv = Buffer.from(process.env.CRYPT_IV, 'hex');
      var cipher = crypto__default["default"].createCipheriv(algorithm, secret, iv);
      var encrypted = cipher.update(text);
      encrypted = Buffer.concat([encrypted, cipher["final"]()]);
      return encrypted.toString('hex');
    }
    /**
     * Metodo de decrypt para las contraseñas y demas
     * @param {*} text 
     */
    ;

    Utils.decrypt = function decrypt(text) {
      var algorithm = 'aes-256-cbc';
      var secret = Buffer.from(process.env.CRYPT_SECRET, 'hex');
      var iv = Buffer.from(process.env.CRYPT_IV, 'hex');
      var encryptedText = Buffer.from(text, 'hex');
      var decipher = crypto__default["default"].createDecipheriv(algorithm, secret, iv);
      var decrypted = decipher.update(encryptedText);
      decrypted = Buffer.concat([decrypted, decipher["final"]()]);
      return decrypted.toString();
    }
    /**
     * 
     * Utiliza una promise para ejecutar un setTimeout y hacer un falso sleep.
     * 
     * @param {*} ms 
     */
    ;

    Utils.sleep = function sleep(ms) {
      var promise_sleep = util__default["default"].promisify(setTimeout);
      return promise_sleep(ms);
    }
    /**
     * Genera dos claves para los metodos crypt y decrypt
     */
    ;

    Utils.generateKeys = function generateKeys() {
      return {
        key: crypto__default["default"].randomBytes(32).toString('hex'),
        iv: crypto__default["default"].randomBytes(16).toString('hex')
      };
    }
    /**
     * "aplana" un objeto jerarquico en una estructura clave-valor.
     * 
     * @param {*} ob 
     * @returns 
     */
    ;

    Utils.flattenObject = function flattenObject(ob) {
      var toReturn = {};
      var flatObject;

      for (var i in ob) {
        if (!ob.hasOwnProperty(i)) {
          continue;
        } //Devolver los arrays tal cual


        if (ob[i] && Array === ob[i].constructor) {
          toReturn[i] = ob[i];
          continue;
        }

        if (typeof ob[i] === 'object') {
          flatObject = Utils.flattenObject(ob[i]);

          for (var x in flatObject) {
            if (!flatObject.hasOwnProperty(x)) {
              continue;
            } //Exclude arrays from the final result


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
    /**
     * Invierte un objeto aplanado recuperando su forma original
     * 
     * @param {*} data 
     * @returns 
     */
    ;

    Utils.unflatten = function unflatten(data) {
      var result = {};

      for (var i in data) {
        var keys = i.split('.');
        keys.reduce(function (r, e, j) {
          return r[e] || (r[e] = isNaN(Number(keys[j + 1])) ? keys.length - 1 == j ? data[i] : {} : []);
        }, result);
      }

      return result;
    }
    /**
     * 
     * @returns 
     */
    ;

    Utils.expressHandler = function expressHandler() {
      return function (fn) {
        return function asyncUtilWrap() {
          var args = [].slice.call(arguments);
          var fnReturn = fn.apply(void 0, args);
          var next = args[args.length - 1];
          return Promise.resolve(fnReturn)["catch"](function (e) {
            return next(e);
          });
        };
      };
    };

    return Utils;
  }();

  function _catch$2(body, recover) {
    try {
      var result = body();
    } catch (e) {
      return recover(e);
    }

    if (result && result.then) {
      return result.then(void 0, recover);
    }

    return result;
  }

  var I18nLoader = /*#__PURE__*/function () {
    function I18nLoader() {
      this.watcher = {};
    }
    /**
     *
     * @param lang
     * @param callback
     */


    var _proto = I18nLoader.prototype;

    _proto.load = function load(custom) {
      try {
        var _this2 = this;

        var lang = custom || process.env.DEFAULT_LANG;

        if (!_this2.currentData) {
          _this2.currentData = {};
        }

        if (!_this2.currentDataFlat) {
          _this2.currentDataFlat = {};
        }

        var file = process.cwd() + "/i18n/lang_" + lang + ".json"; // Initialize watcher.

        _this2.watcher[lang] = chokidar__default["default"].watch(file, {
          ignored: /(^|[/\\])\../,
          // ignore dotfiles
          persistent: true
        }); //Add change watcher

        _this2.watcher[lang].on("change", function (path) {
          return _this2.loadFile(path, lang);
        }); //Initialize file load


        return Promise.resolve(_this2.loadFile(file, lang)).then(function () {});
      } catch (e) {
        return Promise.reject(e);
      }
    }
    /**
     * Carga el archivo de traducciones.
     *
     * @param {*} file
     * @param {*} lang
     */
    ;

    _proto.loadFile = function loadFile(file, lang) {
      try {
        var _this4 = this;

        var readfile = util__default["default"].promisify(fs__default["default"].readFile);
        return Promise.resolve(_catch$2(function () {
          return Promise.resolve(readfile(file, "utf8")).then(function (data) {
            var parsedData = JSON.parse(data);
            _this4.currentDataFlat[lang] = Utils.flattenObject(parsedData);
            _this4.currentData[lang] = parsedData;
          });
        }, function (ex) {
          if ((ex == null ? void 0 : ex.code) === "ENOENT") {
            return console.log("Lang file does not exist. Create it on ./i18n/lang_{xx}.json");
          }

          console.error(ex);
        }));
      } catch (e) {
        return Promise.reject(e);
      }
    }
    /**
     *
     * @param {*} key
     */
    ;

    _proto.translate = function translate(key, lang) {
      try {
        var _temp3 = function _temp3(_result2) {
          return _exit2 ? _result2 : "undefined." + key;
        };

        var _exit2;

        var _this6 = this;

        if (!lang) lang = process.env.DEFAULT_LANG;

        if (_this6.currentDataFlat && _this6.currentDataFlat[lang] && _this6.currentDataFlat[lang][key]) {
          return Promise.resolve(_this6.currentData[lang][key]);
        }

        var _temp4 = function () {
          if (!_this6.currentDataFlat || !_this6.currentDataFlat[lang]) {
            return Promise.resolve(_this6.load(lang)).then(function () {
              if (_this6.currentDataFlat && _this6.currentDataFlat[lang] && _this6.currentDataFlat[key]) {
                var _this5$currentDataFla2 = _this6.currentDataFlat[lang][key];
                _exit2 = 1;
                return _this5$currentDataFla2;
              }
            });
          }
        }();

        return Promise.resolve(_temp4 && _temp4.then ? _temp4.then(_temp3) : _temp3(_temp4));
      } catch (e) {
        return Promise.reject(e);
      }
    };

    return I18nLoader;
  }();

  var JsonResponse = /*#__PURE__*/function () {
    function JsonResponse(success, data, message, total) {
      this.data = data;
      this.success = success;
      this.total = total;
      this.message = message || '';
    }

    var _proto = JsonResponse.prototype;

    _proto.toJson = function toJson() {
      return this;
    };

    return JsonResponse;
  }();

  var TokenGenerator = /*#__PURE__*/function () {
    function TokenGenerator(privateKey, options) {
      this.privateKey = privateKey;
      this.options = options;
    }

    var _proto = TokenGenerator.prototype;

    _proto.sign = function sign(payload) {
      var jwtSignOptions = _extends({}, this.options, {
        jwtid: uuid__namespace.v4()
      });

      return jsonwebtoken__default["default"].sign(payload, this.privateKey, jwtSignOptions);
    };

    _proto.verify = function verify(token) {
      return jsonwebtoken__default["default"].verify(token, this.privateKey, this.options);
    };

    _proto.refresh = function refresh(token) {
      var payload = jsonwebtoken__default["default"].verify(token, this.privateKey, this.options);
      delete payload.sub;
      delete payload.iss;
      delete payload.aud;
      delete payload.iat;
      delete payload.exp;
      delete payload.nbf;
      delete payload.jti; //We are generating a new token, if you are using jwtid during signing, pass it in refreshOptions

      var jwtSignOptions = _extends({}, this.options, {
        jwtid: uuid__namespace.v4()
      }); // The first signing converted all needed options into claims, they are already in the payload


      return jsonwebtoken__default["default"].sign(payload, this.privateKey, jwtSignOptions);
    };

    return TokenGenerator;
  }();

  /**
   * Clase servidor encargada de configurar las rutas.
   *
   * que el codigo se disperse entre diferentes proyectos.
   */

  var Server = /*#__PURE__*/function () {
    /**
     *
     * @param {*} config
     * @param {*} statics
     * @param {*} routes
     */
    function Server(config, statics, routes) {
      this.app = express__default["default"]();
      this.express_config = lodash__default["default"].defaultsDeep(config, {
        helmet: true,
        json: true,
        urlencoded: true,
        compression: true,
        cors: {
          origin: true,
          credentials: true
        },
        fileupload: true,
        socketio: {
          transports: ["websocket"]
        },
        traceRequests: false
      });
      this.statics = statics;
      this.routes = routes;
    }
    /**
     * Inicializa el servidor
     */


    var _proto = Server.prototype;

    _proto.initialize = function initialize() {
      try {
        var _temp3 = function _temp3() {
          return Promise.resolve(_this2.configureRoutes(_this2.routes)).then(function () {
            return Promise.resolve(_this2.errorHandler()).then(function () {});
          });
        };

        var _this2 = this;

        _this2.config(_this2.express_config);

        var _temp4 = function () {
          if (_this2.customizeExpress) {
            return Promise.resolve(_this2.customizeExpress(_this2.app)).then(function () {});
          }
        }();

        return Promise.resolve(_temp4 && _temp4.then ? _temp4.then(_temp3) : _temp3(_temp4));
      } catch (e) {
        return Promise.reject(e);
      }
    }
    /**
     * Funcion sobreescribible para personalizar los componentes cargados en Express
     *
     * Aqui se pueden poner cosas como:
     *
     * this.app.use(cookieParser())... etc
     */
    ;

    _proto.customizeExpress = function customizeExpress() {}
    /**
     * Se encarga de realizar la configuración inicial del servidor
     *
     */
    ;

    _proto.config = function config(_config) {
      if (_config && _config.helmet) {
        //Security
        this.app.use(helmet__default["default"](_config && lodash__default["default"].isObject(_config.helmet) && _config.helmet));
      }

      if (_config && _config.json) {
        //mount json form parser
        this.app.use(express__default["default"].json());
      }

      if (_config && _config.urlencoded) {
        //mount query string parser
        this.app.use(express__default["default"].urlencoded({
          extended: true
        }));
      }

      if (_config && _config.compression) {
        // compress responses
        this.app.use(compression__default["default"]());
      }

      if (_config && _config.cors) {
        //Enable cors to allow external references
        this.app.options("*", cors__default["default"](_config && lodash__default["default"].isObject(_config.cors) && _config.cors));
        this.app.use(cors__default["default"](_config && lodash__default["default"].isObject(_config.cors) && _config.cors));
      }

      if (_config && _config.fileupload) {
        // upload middleware
        this.app.use(fileUpload__default["default"]());
      }

      if (this.statics) {
        //add static paths
        for (var idx in this.statics) {
          this.app.use(idx, express__default["default"]["static"](this.statics[idx]));
        }
      } //Logging


      if (_config && _config.traceRequests === true && process.env.DISABLE_LOGGER != "true") {
        this.app.use(function (request, response, next) {
          request.requestTime = Date.now();
          response.on("finish", function () {
            var pathname = url__default["default"].parse(request.url).pathname;
            var end = Date.now() - request.requestTime;
            var user = request && request.session && request.session.user_id || "";
            console.debug("APIRequest[" + process.pid + "]::. [" + request.method + "] (user:" + user + ")  " + pathname + " |-> took: " + end + " ms");
            console.debug(JSON.stringify(request.body));
          });
          next();
        });
      }
    }
    /**
     * Crea el cargador automatico de rutas
     */
    ;

    _proto.configureRoutes = function configureRoutes(routes) {
      var router = express__default["default"].Router();
      this.app.use(router); //create controllers

      this.loadRoutes(this.app, routes);
    }
    /**
     * Instancia la lista de rutas disponibles
     * @param apps
     * @returns {*}
     */
    ;

    _proto.loadRoutes = function loadRoutes(app, routes) {
      if (!routes) return;

      for (var _iterator = _createForOfIteratorHelperLoose(routes), _step; !(_step = _iterator()).done;) {
        var route = _step.value;

        if (!route) {
          console.warn("Empty route");
          continue;
        }

        var router = route.configure();

        if (!lodash__default["default"].isEmpty(route.routes)) {
          var exAsync = Utils.expressHandler();
          console.log("loading shorthand routes");

          for (var path in route.routes) {
            var cfg = route.routes[path];

            for (var method in cfg) {
              router[method](path, exAsync(cfg[method]));
            }
          }
        }

        if (router) {
          app.use(router);
        }
      }
    }
    /**
     * Errores
     */
    ;

    _proto.errorHandler = function errorHandler() {
      // error handler
      this.app.use(function (err, req, res, next) {
        var jsRes = new JsonResponse();
        jsRes.success = false;
        jsRes.message = err.message; //!FIXME protect error displaying in REST Responses

        console.error(err);
        res.status(500).json(jsRes.toJson());
      });
    };

    return Server;
  }();

  /**
   * Inicializa la escucha del server en modo cluster
   */

  var ClusterServer = /*#__PURE__*/function (_EventEmitter) {
    _inheritsLoose(ClusterServer, _EventEmitter);

    function ClusterServer(app) {
      var _this;

      _this = _EventEmitter.call(this) || this;

      if (!process.env.PORT) {
        console.log("Using 3000 as default port. Customize via env PORT.");
      }

      _this.port = _this.normalizePort(process.env.PORT || 3000);
      _this.clustered = process.env.CLUSTERED;
      _this.workers = [];
      _this.app = app;

      _this.executeOnlyMain = function () {};

      return _this;
    }

    var _proto = ClusterServer.prototype;

    _proto.setServerCls = function setServerCls(cls) {
      this.server = cls;
    }
    /**
     * Iniciar el servidor en el puerto y con la configuración seleccionadas.
     */
    ;

    _proto.start = function start() {
      try {
        var _this3 = this;

        var _temp2 = function () {
          if (_this3.clustered == "true") {
            _this3.initClustered();
          } else {
            _this3.configureSocketIO();

            _this3.executeOnlyMain();

            return Promise.resolve(_this3.initUnclustered()).then(function () {});
          }
        }();

        return Promise.resolve(_temp2 && _temp2.then ? _temp2.then(function () {}) : void 0);
      } catch (e) {
        return Promise.reject(e);
      }
    }
    /**
     * Inicializa el servidor de socketio en el puerto siguiente al configurado.
     *
     * Se puede desactivar mediante la config socketio: false al realizar el App.init()
     */
    ;

    _proto.configureSocketIO = function configureSocketIO() {
      if (this.server.express_config && this.server.express_config.socketio) {
        this.app.io = new socket_io.Server(this.server.express_config && this.server.express_config.socketio);
        this.app.io.listen(this.port + 1);
      }
    }
    /**
     * Inicializa la clase server encargada del control de las solicitudes en forma multiproceso.
     *
     */
    ;

    _proto.initClustered = function initClustered() {
      try {
        var _this5 = this;

        var _temp4 = function () {
          if (cluster__default["default"].isPrimary) {
            _this5.configureSocketIO();

            _this5.executeOnlyMain();

            var messages = new ClusterMessages__default["default"]();
            messages.on("event", function (msg, callback) {
              if (msg && msg.event) {
                if (process.env.DEBUG_EVENTS == true) {
                  console.debug("Received '" + msg.event + "' from " + msg.props.owner + " at Master");
                } //Desencadenar en el proceso principal tambien


                _this5.app.events.emit(msg.event, msg.props, callback);
              }
            }); //Count the machine's CPUs

            var cpuCount = os__default["default"].cpus().length; //Create a worker for each CPU

            for (var idx = 0; idx < cpuCount; idx += 1) {
              _this5.initWorker();
            } //Listen for dying workers


            cluster__default["default"].on("exit", function (worker) {
              //Replace the dead worker, we're not sentimental
              console.log("Worker " + worker.id + " died :(");

              _this5.initWorker();
            });
          } else {
            return Promise.resolve(_this5.initUnclustered()).then(function () {
              console.log("Worker " + process.pid + " started");
            });
          }
        }();

        //Launch cluster
        return Promise.resolve(_temp4 && _temp4.then ? _temp4.then(function () {}) : void 0);
      } catch (e) {
        return Promise.reject(e);
      }
    }
    /**
     * Inicia un worker
     */
    ;

    _proto.initWorker = function initWorker() {
      var worker = cluster__default["default"].fork();
      console.log("Running worker " + worker.process.pid);
      this.workers.push(worker);
    }
    /**
     * Inicializa la clase server encargada del control de las solicitudes en un unico proceso.
     *
     */
    ;

    _proto.initUnclustered = function initUnclustered() {
      try {
        var _this7 = this;

        _this7.server.port = _this7.port; //create http server

        var server = http__default["default"].Server(_this7.server.app);
        return Promise.resolve(_this7.server.initialize()).then(function () {
          function _temp8() {
            function _temp6() {
              //add error handler
              server.on("error", function (err) {
                _this7.handleErrors(err, _this7.server.port);
              }); //start listening on port

              server.on("listening", function () {
                console.log("Server Worker running on port: " + _this7.port + "!");

                _this7.emit("listening", _this7.port);
              });

              if (process.env.SSL && process.env.SSL == "true") {
                if (!process.env.SSL_KEY || !process.env.SSL_CERT || !process.env.SSL_PASS) {
                  console.error("Invalid SSL configuration. SLL_KEY, SSL_CERT and SSL_PASS needed");
                  process.exit(0);
                }

                var key = fs__default["default"].readFileSync(path__default["default"].resolve(process.cwd(), process.env.SSL_KEY || "key.pem"));
                var cert = fs__default["default"].readFileSync(path__default["default"].resolve(process.cwd(), process.env.SSL_CERT || "cert.pem"));
                var options = {
                  key: key,
                  cert: cert,
                  passphrase: process.env.SSL_PASS
                };

                if (!process.env.SSL_PORT) {
                  console.log("Using 3443 as ssl default port. Customize via env SSL_PORT.");
                }

                var sslPort = _this7.normalizePort(process.env.SSL_PORT || 3443);

                var serverSsl = https__default["default"].createServer(options, _this7.server.app);
                serverSsl.listen(sslPort); //add error handler

                serverSsl.on("error", function (err) {
                  _this7.handleErrors(err, sslPort);
                }); //start listening on port

                serverSsl.on("listening", function () {
                  console.log("Server Worker running on port: " + sslPort + "!");

                  _this7.emit("listening_ssl", sslPort);
                });
              }
            }

            //listen on provided ports
            server.listen(_this7.server.port);

            var _temp5 = function () {
              if (_this7.server.afterListen) return Promise.resolve(_this7.server.afterListen()).then(function () {});
            }();

            return _temp5 && _temp5.then ? _temp5.then(_temp6) : _temp6(_temp5);
          }

          var _temp7 = function () {
            if (_this7.server.beforeListen) return Promise.resolve(_this7.server.beforeListen()).then(function () {});
          }();

          return _temp7 && _temp7.then ? _temp7.then(_temp8) : _temp8(_temp7);
        });
      } catch (e) {
        return Promise.reject(e);
      }
    }
    /**
     * Controla los posibles errores de formato en el puerto
     * @param val
     * @returns {*}
     */
    ;

    _proto.normalizePort = function normalizePort(val) {
      var port = parseInt(val, 10);

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
    ;

    _proto.handleErrors = function handleErrors(error, port) {
      if (error.syscall !== "listen") {
        throw error;
      }

      var bind = typeof port === "string" ? "Pipe " + port : "Port " + port; //handle specific listen errors with friendly messages

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
    };

    return ClusterServer;
  }(events.EventEmitter);

  /**
   * Clase encargada de la generacion de eventos.
   */

  var EventHandler = /*#__PURE__*/function (_EventEmitter) {
    _inheritsLoose(EventHandler, _EventEmitter);

    function EventHandler(app) {
      var _this;

      _this = _EventEmitter.call(this) || this;
      _this.messages = new ClusterMessages__default["default"]();
      _this.app = app; //Se recibe el singleton App para evitar referencias cruzadas

      if (cluster__default["default"].isWorker) {
        // Levanto, en los worker, la escucha para recibir los eventos en broadcast de los demas hilos
        _this.messages.on("event", function (msg, callback) {
          if (msg && msg.event && process.pid !== msg.props.owner) {
            if (process.env.DEBUG_EVENTS == true) {
              console.debug("Receiving broadcast " + msg.event + " - " + process.pid);
            }

            _EventEmitter.prototype.emit.call(_assertThisInitialized(_this), msg.event, _extends({}, msg.props), callback);
          }
        });
      }

      return _this;
    }
    /**
     * Sobreescribir el emitter para notificar a los hijos
     *
     * @param {*} evt
     * @param {*} props
     */


    var _proto = EventHandler.prototype;

    _proto.emit = function emit(evt, props, callback) {
      //Desencadenar en local
      _EventEmitter.prototype.emit.call(this, evt, props, callback);

      if (evt && props && cluster__default["default"].isWorker && process.pid !== props.owner) {
        if (process.env.DEBUG_EVENTS == true) {
          console.debug(evt + " -> Firing from " + process.pid + " to master");
        }

        if (!props) {
          props = {};
        }

        props.owner = process.pid;
        this.messages.send("event", {
          event: evt,
          props: _extends({}, props)
        }, callback);
      }

      if (evt && props && cluster__default["default"].isPrimary && this.app && this.app.server && this.app.server.workers) {
        if (process.env.DEBUG_EVENTS == true) {
          console.debug(evt + " -> Firing from master to workers");
        }

        this.messages.send("event", {
          event: evt,
          props: _extends({}, props)
        }, callback);
      }
    };

    return EventHandler;
  }(events.EventEmitter);

  var _configure = log4js__default["default"].configure,
      getLogger = log4js__default["default"].getLogger;

  var Logger = /*#__PURE__*/function () {
    function Logger() {}

    Logger.configure = function configure() {
      try {
        var readfile = util__default["default"].promisify(fs__default["default"].readFile);
        return Promise.resolve(readfile(path__default["default"].resolve(process.cwd(), "./log4js.json"), "utf8")).then(function (json) {
          _configure(JSON.parse(json)); //Nota para el futuro:
          // Esto sobreescribe los metodos de console.log
          // Es necesario que la sitaxis se mantenga tal cual....


          (function () {
            var log_logger = getLogger("log");
            var error_logger = getLogger("error");
            var debug_logger = getLogger("debug");

            console.log = function () {
              var args = Array.prototype.slice.call(arguments); // log.apply(this, args);

              log_logger.log("info", args[0]);
            };

            console.error = function () {
              var args = Array.prototype.slice.call(arguments); // error.apply(this, args);

              error_logger.log("error", args[0]);
            };

            console.info = function () {
              var args = Array.prototype.slice.call(arguments); // info.apply(this, args);

              log_logger.log("info", args[0]);
            };

            console.debug = function () {
              /*if (global.settings.debug.value) {*/
              var args = Array.prototype.slice.call(arguments); // debug.apply(this, [args[1], args[2]]);

              debug_logger.log("debug", args[0]);
            };

            console.custom = function (logger, level, message) {
              var custom_logger = getLogger(logger);
              custom_logger.log(level, message);
            };
          })();
        });
      } catch (e) {
        return Promise.reject(e);
      }
    };

    return Logger;
  }();

  function _catch$1(body, recover) {
    try {
      var result = body();
    } catch (e) {
      return recover(e);
    }

    if (result && result.then) {
      return result.then(void 0, recover);
    }

    return result;
  }

  var AuthController = /*#__PURE__*/function () {
    function AuthController(publicPathsList, AuthHandler) {
      this.router = express__default["default"].Router();
      this.publicPathsList = [].concat(publicPathsList, ["/login"]);
      this.AuthHandler = AuthHandler;
    }

    var _proto = AuthController.prototype;

    _proto.configure = function configure() {
      var _this = this;

      var exAsync = Utils.expressHandler();
      this.router.use(exAsync(function () {
        return _this.check.apply(_this, [].slice.call(arguments));
      }));
      this.router.post("/login", exAsync(function () {
        return _this.loginPost.apply(_this, [].slice.call(arguments));
      }));
      this.router.post("/logout", exAsync(function () {
        return _this.logout.apply(_this, [].slice.call(arguments));
      }));
      return this.router;
    }
    /**
     * Controla que los usuarios tengan sesion para acceder a los metodos privados de la API
     *
     * @param {*} request
     * @param {*} response
     * @param {*} next
     */
    ;

    _proto.check = function check(request, response, next) {
      try {
        var _exit3;

        var _this3 = this;

        return Promise.resolve(_catch$1(function () {
          var _exit2;

          //Rutas ublicas
          for (var _iterator = _createForOfIteratorHelperLoose(_this3.publicPathsList), _step; !(_step = _iterator()).done;) {
            var path = _step.value;
            var expr = pathToRegexp.pathToRegexp(path);

            if (expr.exec(url__default["default"].parse(request.url).pathname) !== null) {
              return next();
            }
          }

          return Promise.resolve(_this3.AuthHandler.check(request)).then(function (_this2$AuthHandler$ch) {
            if (_this2$AuthHandler$ch) {
              var _next2 = next();

              _exit3 = 1;
              return _next2;
            }

            return response.status(403).json(new JsonResponse(false, null, "Forbidden").toJson());
          });
        }, function (ex) {
          console.error(ex);
          return response.status(403).json(new JsonResponse(false, null, "Forbidden").toJson());
        }));
      } catch (e) {
        return Promise.reject(e);
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
    ;

    _proto.loginPost = function loginPost(request, response) {
      try {
        var _temp3 = function _temp3(_result) {
          return _exit5 ? _result : response.status(401).json(new JsonResponse(false, null, "Unauthorized - Missing parameters").toJson());
        };

        var _exit5;

        var _this5 = this;

        var _temp4 = function () {
          if (request.body.username) {
            return _catch$1(function () {
              return Promise.resolve(_this5.AuthHandler.validate(request, request.body.username, request.body.password)).then(function (data) {
                if (data) {
                  var _response$status$json4 = response.status(200).json(new JsonResponse(true, data).toJson());

                  _exit5 = 1;
                  return _response$status$json4;
                }

                var _response$status$json2 = response.status(401).json(new JsonResponse(false, null, "Unauthorized - Incorrect credentials").toJson());

                _exit5 = 1;
                return _response$status$json2;
              });
            }, function (ex) {
              console.error(ex);

              var _response$status$json3 = response.status(401).json(new JsonResponse(false, null, "Unauthorized - Error, check log").toJson());

              _exit5 = 1;
              return _response$status$json3;
            });
          }
        }();

        return Promise.resolve(_temp4 && _temp4.then ? _temp4.then(_temp3) : _temp3(_temp4));
      } catch (e) {
        return Promise.reject(e);
      }
    }
    /**
     * Cierra la sesion del usuario
     *
     * @param {*} request
     * @param {*} response
     */
    ;

    _proto.logout = function logout(request, response) {
      try {
        var _temp7 = function _temp7(_result2) {
          return _exit7 ? _result2 : response.status(200).json(new JsonResponse(true).toJson());
        };

        var _exit7;

        var _this7 = this;

        var _temp8 = function () {
          if (_this7.AuthHandler.logout) {
            //Depende de que el authHandler implementado pueda realizar esta accion
            return _catch$1(function () {
              return Promise.resolve(_this7.AuthHandler.logout(request)).then(function () {
                var _response$status$json5 = response.status(200).json(new JsonResponse(true).toJson());

                _exit7 = 1;
                return _response$status$json5;
              });
            }, function (ex) {
              console.error(ex);

              var _response$status$json6 = response.status(500).json(new JsonResponse(false, null, ex).toJson());

              _exit7 = 1;
              return _response$status$json6;
            });
          }
        }();

        return Promise.resolve(_temp8 && _temp8.then ? _temp8.then(_temp7) : _temp7(_temp8));
      } catch (e) {
        return Promise.reject(e);
      }
    };

    return AuthController;
  }();

  var IAuthHandler = function IAuthHandler() {
    if (!this.check) {
      throw new Error("AuthHandler must have 'check' vethod");
    }

    if (!this.validate) {
      throw new Error("AuthHandler must have 'validate' vethod");
    } // logout method is optional

  };

  var JwtAuthHandler = /*#__PURE__*/function (_IAuthHandler) {
    _inheritsLoose(JwtAuthHandler, _IAuthHandler);

    function JwtAuthHandler(UserDao) {
      var _this;

      _this = _IAuthHandler.call(this) || this;
      _this.tokenGenerator = new TokenGenerator(process.env.JWT_SECRET, {
        audience: process.env.JWT_AUDIENCE,
        issuer: process.env.JWT_ISSUER,
        subject: process.env.JWT_SUBJECT,
        algorithm: process.env.JWT_ALGORITHM,
        expiresIn: process.env.JWT_EXPIRES
      });

      if (!UserDao) {
        throw new Error("Need 'UserDao' for user validation. Create 'UserDao' class extending 'IUserDao'");
      }

      _this.userDao = UserDao;
      return _this;
    }
    /**
     * Metodo encargado de realizar la comprobacion para validar si la sesion del usuario es válida
     * 
     * @param {*} request 
     */


    var _proto = JwtAuthHandler.prototype;

    _proto.check = function check(request) {
      try {
        var _this3 = this;

        if (request.headers.authorization) {
          var token = (request.headers.authorization || '').split(' ')[1] || '';

          if (!token) {
            console.error("Token needed");
            return Promise.resolve(false);
          }

          try {
            var decoded = _this3.tokenGenerator.verify(token);

            var sub = decoded.sub,
                username = decoded.username,
                exp = decoded.exp;

            if (!sub || !username || moment__default["default"](exp).isAfter(new Date())) {
              return Promise.resolve(false);
            } //Si la sesion es valida, lo introducimos en el contexto de la solicitud


            request.session = _extends({}, request.session, decoded);
            return Promise.resolve(true);
          } catch (ex) {
            console.error(ex);
            return Promise.resolve(false);
          }
        }

        return Promise.resolve(false);
      } catch (e) {
        return Promise.reject(e);
      }
    }
    /**
     * Método encargado de realizar la validación de un usuario. Utiliza IUserDao como interfaz para la realización de la query a BD.
     * 
     * @param {*} username 
     * @param {*} password 
     */
    ;

    _proto.validate = function validate(request, username, password) {
      try {
        var _this5 = this;

        return Promise.resolve(_this5.userDao.findByUsername(username)).then(function (user) {
          return user && user.username === username && user.password === Utils.encrypt(password) ? _this5.tokenGenerator.sign(lodash__default["default"].omit(user, ['password'])) : false;
        });
      } catch (e) {
        return Promise.reject(e);
      }
    };

    return JwtAuthHandler;
  }(IAuthHandler);

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

  var CookieAuthHandler = /*#__PURE__*/function (_IAuthHandler) {
    _inheritsLoose(CookieAuthHandler, _IAuthHandler);

    function CookieAuthHandler(UserDao) {
      var _this;

      _this = _IAuthHandler.call(this) || this;

      if (!UserDao) {
        throw new Error("Need 'UserDao' for user validation. Create 'UserDao' class extending 'IUserDao'");
      }

      _this.userDao = UserDao;
      return _this;
    }
    /**
     * Metodo encargado de realizar la comprobacion para validar si la sesion del usuario es válida
     *
     * @param {*} request
     */


    var _proto = CookieAuthHandler.prototype;

    _proto.check = function check(request) {
      try {
        var _temp3 = function _temp3(_result) {
          return _exit2 ? _result : request.session && request.session.username ? true : false;
        };

        var _exit2;

        var _this3 = this;

        var _temp4 = function () {
          if (request.headers.authorization) {
            //Si se recibe por Auth Basic
            var token = (request.headers.authorization || "").split(" ")[1] || "";
            var creds = Buffer.from(token, "base64").toString().split(":");
            var login = creds[0];
            var password = creds[1];
            return Promise.resolve(_this3.validate(request, login, password)).then(function (_this2$validate) {
              if (!_this2$validate) {
                _exit2 = 1;
                return false;
              }

              return _exit2 = true;
            });
          }
        }();

        return Promise.resolve(_temp4 && _temp4.then ? _temp4.then(_temp3) : _temp3(_temp4));
      } catch (e) {
        return Promise.reject(e);
      }
    }
    /**
     * Método encargado de realizar la validación de un usuario. Utiliza IUserDao como interfaz para la realización de la query a BD.
     *
     * @param {*} username
     * @param {*} password
     */
    ;

    _proto.validate = function validate(request, username, password) {
      try {
        var _this5 = this;

        return Promise.resolve(_this5.userDao.findByUsername(username)).then(function (user) {
          if (user && user.username === username && user.password === Utils.encrypt(password)) {
            request.session = _extends({}, request.session, lodash__default["default"].omit(user, ["password"]));
            return true;
          }

          return false;
        });
      } catch (e) {
        return Promise.reject(e);
      }
    }
    /**
     *
     * @param {*} request
     */
    ;

    _proto.logout = function logout(request) {
      return new Promise(function (resolve) {
        if (request.session) {
          request.session.destroy(resolve);
        }
      });
    };

    return CookieAuthHandler;
  }(IAuthHandler);

  var KnexConnector = /*#__PURE__*/function () {
    function KnexConnector() {}

    var _proto = KnexConnector.prototype;

    _proto.init = function init(config) {
      /**
       * References the current connection of the app
       * @type {Knex}
       * @public
       */
      this.connection = Knex__default["default"](config);
    }
    /**
     * Configura de forma global los aliases de las columnas para utilizar en FQL.
     * 
     * La estructura es 
     * {
            "table1": {
                "alias1": "column1",
                "alias2": "column2"
            },
            "table2": {
                "alias1": "column1"
            }
        }
     *
     * @param {*} aliases 
     */
    ;

    _proto.setColumnAliases = function setColumnAliases(aliases) {
      this.columnAliases = aliases;
    };

    _proto.test = function test() {
      return this.connection.raw('select 1+1 as result');
    };

    return KnexConnector;
  }();

  var KnexConnector$1 = new KnexConnector();

  var KnexFilterParser = /*#__PURE__*/function () {
    function KnexFilterParser() {}

    /**
     *
     * @param {*} builder
     * @param {*} string
     * @returns
     */
    KnexFilterParser.parseQueryString = function parseQueryString(builder, string, tableName) {
      var options = {
        allowGlobalSearch: true,
        caseInsensitive: true
      }; //Agregar los aliases en caso de que se hayan configurado de forma global

      if (KnexConnector$1.columnAliases && KnexConnector$1.columnAliases[tableName]) {
        options.aliases = KnexConnector$1.columnAliases[tableName];
      } //Options


      if (KnexConnector$1.caseInsensitive !== undefined) {
        options.caseInsensitive = KnexConnector$1.caseInsensitive;
      }

      if (KnexConnector$1.allowGlobalSearch !== undefined) {
        options.allowGlobalSearch = KnexConnector$1.allowGlobalSearch;
      }

      var parser = new fqlParser.FQLParser(options);
      var data = parser.parse(string);
      return new fqlParser.KnexParser(tableName).toKnex(builder, data);
    }
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
    ;

    KnexFilterParser.parseFilters = function parseFilters(builder, filter, tableName) {
      var query = builder;

      for (var prop in filter) {
        var elm = filter[prop];

        if (typeof elm === "object") {
          switch (elm.type) {
            case "fql":
              query = KnexFilterParser.parseQueryString(query, elm.value, tableName);
              break;

            case "date":
            case "between":
              if (elm.start && elm.end) {
                query = query.whereBetween(prop, [elm.start, elm.end]);
              }

              if (elm.start && !elm.end) {
                query = query.where(prop, ">=", elm.start);
              }

              if (!elm.start && elm.end) {
                query = query.where(prop, ">=", elm.end);
              }

              break;

            case "dateraw":
            case "betweenraw":
              if (elm.start && elm.end) {
                query = query.whereRaw(prop + " BETWEEN ? AND ?", [elm.start, elm.end]);
              }

              if (elm.start && !elm.end) {
                query = query.whereRaw(prop + " >= ?", [elm.start]);
              }

              if (!elm.start && elm.end) {
                query = query.whereRaw(prop + " >= ?", [elm.end]);
              }

              break;

            case "jsonb":
              query = query.whereRaw(prop + " ILIKE ?", ["%" + elm.value + "%"]);
              break;

            case "full-text-psql":
              query = query.whereRaw("to_tsvector(" + prop + "::text) @@ to_tsquery(?)", [elm.value]);
              break;

            case "greater":
            case "greaterraw":
              query = query.whereRaw(prop + " > ?", [elm.value]);
              break;

            case "greaterEq":
            case "greaterEqraw":
              query = query.whereRaw(prop + " >= ?", [elm.value]);
              break;

            case "less":
            case "lessraw":
              query = query.whereRaw(prop + " < ?", [elm.value]);
              break;

            case "lessEq":
            case "lessEqraw":
              query = query.whereRaw(prop + " <= ?", [elm.value]);
              break;

            case "exists":
              query = query.whereExists(prop);
              break;

            case "notexists":
              query = query.whereNotExists(prop);
              break;

            case "exact":
            case "exactraw":
              query = query.whereRaw(prop + " = ?", [elm.value]);
              break;

            case "in":
              var propComplex = prop;

              if (propComplex.includes(",")) {
                propComplex = prop.split(",");
              }

              if (!Array.isArray(elm.value) && elm.value != undefined) {
                query = query.whereIn(propComplex, elm.value.split(","));
              } else {
                if (elm.value != undefined) {
                  query = query.whereIn(propComplex, elm.value);
                }
              }

              break;

            case "inraw":
              if (!Array.isArray(elm.value) && elm.value != undefined) {
                query = query.whereRaw(prop + " IN (?)", [elm.value.split(",").map(function (e) {
                  return "'" + e + "'";
                }).join(",")]);
              } else {
                if (elm.value != undefined) {
                  query = query.whereRaw(prop + " IN (?)", [elm.value.map(function (e) {
                    return "'" + e + "'";
                  }).join(",")]);
                }
              }

              break;

            case "not":
            case "notraw":
              query = query.whereRaw(prop + " != ?", [elm.value]);
              break;

            case "like":
            case "likeraw":
              var value_likeraw = Utils.replaceAll(elm.value, "*", "%");
              query = query.whereRaw(" " + prop + " LIKE ?", [value_likeraw]);
              break;

            case "notlike":
            case "notlikeraw":
              var value_nolikeraw = Utils.replaceAll(elm.value, "*", "%");
              query = query.whereRaw(" " + prop + " NOT LIKE ?", [value_nolikeraw]);
              break;

            case "likeI":
              var value_rawilike = Utils.replaceAll(elm.value, "*", "%");
              query = query.whereRaw(" " + prop + " ILIKE ?", [value_rawilike]);
              break;

            case "notlikeI":
              var value_notrawilike = Utils.replaceAll(elm.value, "*", "%");
              query = query.whereRaw(" " + prop + " NOT ILIKE ?", [value_notrawilike]);
              break;

            case "null":
            case "nullraw":
              query = query.whereRaw(prop + " is NULL");
              break;

            case "notnull":
            case "notnullraw":
              query = query.whereRaw(prop + " is not NULL");
              break;
          }
        } else {
          //Si el valor no es un objeto se devuelve
          query = query.where(prop, elm);
        }
      } // console.log(query.toSQL());


      return query;
    }
    /**
     * Conversion de un objeto {property: XX, direction: ASC|DESC - ascend|descend} a un ORDER BY
     *
     * @param {*} sorts
     */
    ;

    KnexFilterParser.parseSort = function parseSort(sort) {
      if (!sort.field || !sort.direction) {
        return 1;
      }

      var direction = "ASC";

      if (sort.direction === "descend") {
        direction = "DESC";
      }

      return sort.field + " " + direction;
    };

    return KnexFilterParser;
  }();

  /**
   * Crear un dao con los métodos básicos
   */

  var BaseKnexDao = /*#__PURE__*/function () {
    function BaseKnexDao() {
      this.tableName = "";
    }

    var _proto = BaseKnexDao.prototype;

    _proto.loadAllData = function loadAllData(start, limit) {
      return KnexConnector$1.connection.select("*").from(this.tableName).limit(limit || 10000).offset(start);
    };

    _proto.loadFilteredData = function loadFilteredData(filters, start, limit) {
      try {
        var _this2 = this;

        var sorts = 1;

        if (filters.sort) {
          sorts = KnexFilterParser.parseSort(filters.sort);
        }

        return Promise.resolve(KnexConnector$1.connection.from(_this2.tableName).where(function (builder) {
          return KnexFilterParser.parseFilters(builder, lodash__default["default"].omit(filters, ["sort", "start", "limit"]), _this2.tableName);
        }).orderByRaw(sorts).limit(limit).offset(start));
      } catch (e) {
        return Promise.reject(e);
      }
    };

    _proto.countFilteredData = function countFilteredData(filters) {
      try {
        var _this4 = this;

        return Promise.resolve(KnexConnector$1.connection.from(_this4.tableName).where(function (builder) {
          return KnexFilterParser.parseFilters(builder, lodash__default["default"].omit(filters, ["sort", "start", "limit"]), _this4.tableName);
        }).count("id", {
          as: "total"
        })).then(function (data) {
          return data && data[0].total;
        });
      } catch (e) {
        return Promise.reject(e);
      }
    };

    _proto.loadById = function loadById(objectId) {
      try {
        var _this6 = this;

        return Promise.resolve(KnexConnector$1.connection.from(_this6.tableName).where("id", objectId)).then(function (data) {
          return data && data[0] ? data[0] : null;
        });
      } catch (e) {
        return Promise.reject(e);
      }
    };

    _proto.save = function save(object) {
      return KnexConnector$1.connection.from(this.tableName).insert(object).returning("*");
    };

    _proto.update = function update(objectId, newObject) {
      return KnexConnector$1.connection.from(this.tableName).where("id", objectId).update(newObject).returning("*");
    };

    _proto["delete"] = function _delete(objectId) {
      try {
        var _this8 = this;

        return Promise.resolve(_this8.loadById(objectId)).then(function (existing) {
          if (!existing) {
            throw "NotFound";
          }

          return KnexConnector$1.connection.from(_this8.tableName).where("id", objectId)["delete"]();
        });
      } catch (e) {
        return Promise.reject(e);
      }
    };

    return BaseKnexDao;
  }();

  var IUserDao = /*#__PURE__*/function (_BaseKnexDao) {
    _inheritsLoose(IUserDao, _BaseKnexDao);

    function IUserDao(tableName) {
      var _this;

      _this = _BaseKnexDao.call(this, tableName) || this;

      if (!_this.findByUsername) {
        throw new Error("AuthHandler must have 'findByUsername' method");
      }

      return _this;
    }

    return IUserDao;
  }(BaseKnexDao);

  function _catch(body, recover) {
    try {
      var result = body();
    } catch (e) {
      return recover(e);
    }

    if (result && result.then) {
      return result.then(void 0, recover);
    }

    return result;
  }

  var BaseController = /*#__PURE__*/function () {
    function BaseController() {
      this.router = express__default["default"].Router();
      this.routes = {}; //Example routes shorthand

      /*
       {
          "/": {
              "get": this.listEntidad.bind(this),
              "post": this.listEntidad.bind(this)
          }
       } 
       */
    }

    var _proto = BaseController.prototype;

    _proto.configure = function configure(entity, config) {
      var _this = this;

      if (!entity) {
        return this.router;
      }

      var exAsync = Utils.expressHandler();
      this.router.get("/" + entity, exAsync(function () {
        return _this.listEntidad.apply(_this, [].slice.call(arguments));
      }));
      this.router.post("/" + entity + "/list", exAsync(function () {
        return _this.listEntidad.apply(_this, [].slice.call(arguments));
      }));
      this.router.get("/" + entity + "/:id", exAsync(function () {
        return _this.getEntidad.apply(_this, [].slice.call(arguments));
      }));
      this.router.post("/" + entity, exAsync(function () {
        return _this.saveEntidad.apply(_this, [].slice.call(arguments));
      }));
      this.router.put("/" + entity + "/:id", exAsync(function () {
        return _this.updateEntidad.apply(_this, [].slice.call(arguments));
      }));
      this.router["delete"]("/" + entity + "/:id", exAsync(function () {
        return _this.deleteEntidad.apply(_this, [].slice.call(arguments));
      }));
      this.service = config.service;
      this.table = config.table;
      return this.router;
    }
    /**
     * Lista entidades en la aplicacion, es posible enviarle parametros de filtrado.
     *
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
    ;

    _proto.listEntidad = function listEntidad(request, response, next) {
      try {
        var _this3 = this;

        var _temp2 = _catch(function () {
          var service = new _this3.service(null, _this3.table);
          var filters = request.method === "POST" ? request.body : request.query && request.query.filters ? JSON.parse(request.query.filters) : {};
          return Promise.resolve(service.list(filters, filters.start, filters.limit)).then(function (data) {
            var jsRes = new JsonResponse(true, data.data, null, data.total);
            response.json(jsRes.toJson());
          });
        }, function (e) {
          next(e);
        });

        return Promise.resolve(_temp2 && _temp2.then ? _temp2.then(function () {}) : void 0);
      } catch (e) {
        return Promise.reject(e);
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
    ;

    _proto.getEntidad = function getEntidad(request, response, next) {
      try {
        var _this5 = this;

        var _temp4 = _catch(function () {
          var service = new _this5.service(null, _this5.table);
          return Promise.resolve(service.loadById(request.params.id)).then(function (data) {
            var jsRes = new JsonResponse(true, data);
            var code = 200;

            if (data == null) {
              code = 404;
              var message = "Element not found";
              jsRes = new JsonResponse(false, null, message, 0);
            }

            response.status(code).json(jsRes.toJson());
          });
        }, function (e) {
          console.error(e);
          var message = "";

          if (e.code == "22P02") {
            //PostgreSQL error Code form string_to_UUID
            message = "Expected uiid";
          }

          var jsRes = new JsonResponse(false, null, message, 0);
          response.status(400).json(jsRes.toJson());
        });

        return Promise.resolve(_temp4 && _temp4.then ? _temp4.then(function () {}) : void 0);
      } catch (e) {
        return Promise.reject(e);
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
    ;

    _proto.saveEntidad = function saveEntidad(request, response, next) {
      try {
        var _this7 = this;

        var _temp6 = _catch(function () {
          var service = new _this7.service(null, _this7.table);
          return Promise.resolve(service.save(request.body)).then(function (data) {
            var jsRes = new JsonResponse(true, data && data[0] || {
              id: request.body.id
            });
            response.setHeader("Location", "/entity/" + jsRes.data.id);
            response.status(201).json(jsRes.toJson());
          });
        }, function (e) {
          next(e);
        });

        return Promise.resolve(_temp6 && _temp6.then ? _temp6.then(function () {}) : void 0);
      } catch (e) {
        return Promise.reject(e);
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
    ;

    _proto.updateEntidad = function updateEntidad(request, response, next) {
      try {
        var _this9 = this;

        var _temp8 = _catch(function () {
          var service = new _this9.service(null, _this9.table);
          return Promise.resolve(service.update(request.params.id, request.body)).then(function (data) {
            var jsRes = new JsonResponse(true, data && data[0] || {
              id: request.body.id
            });
            response.json(jsRes.toJson());
          });
        }, function (e) {
          next(e);
        });

        return Promise.resolve(_temp8 && _temp8.then ? _temp8.then(function () {}) : void 0);
      } catch (e) {
        return Promise.reject(e);
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
    ;

    _proto.deleteEntidad = function deleteEntidad(request, response, next) {
      try {
        var _this11 = this;

        var _temp10 = _catch(function () {
          var service = new _this11.service(null, _this11.table);
          return Promise.resolve(service["delete"](request.params.id)).then(function (data) {
            var jsRes = new JsonResponse(true, data);
            response.status(204).json(jsRes.toJson());
          });
        }, function (e) {
          console.error(e);

          if (e == "NotFound") {
            var message = "Element not found";
            var jsRes = new JsonResponse(false, null, message, 0);
            response.status(404).json(jsRes.toJson());
          } else {
            next(e);
          }
        });

        return Promise.resolve(_temp10 && _temp10.then ? _temp10.then(function () {}) : void 0);
      } catch (e) {
        return Promise.reject(e);
      }
    };

    return BaseController;
  }();

  var BaseService = /*#__PURE__*/function () {
    function BaseService(cls, table) {
      if (cls) {
        this.dao = new cls();
      } else {
        this.dao = new BaseKnexDao(); //El sistema por defecto utiliza knex, si se pasa un dao personalizado se puede sobreescribir este comportamiento
      }

      if (table) {
        this.dao.tableName = table;
      }
    }
    /**
     * Obtencion de una lista de elementos.
     *
     * filters, es opcional. Si no se pasan se devuelve lo que hay ;
     */


    var _proto = BaseService.prototype;

    _proto.list = function list(filters, start, limit) {
      try {
        var _this2 = this;

        //Pagination
        var st = start || 0;
        var lm = limit || 1000; //Default limit

        var response = {};
        return Promise.resolve(_this2.dao.countFilteredData(filters, st, lm)).then(function (_this$dao$countFilter) {
          var _exit;

          function _temp2(_result) {
            return _exit ? _result : Promise.resolve(_this2.dao.loadAllData(start, limit)).then(function (_this$dao$loadAllData) {
              response.data = _this$dao$loadAllData;
              return response;
            });
          }

          response.total = _this$dao$countFilter;

          var _temp = function () {
            if (filters && Object.keys(filters).length !== 0) {
              return Promise.resolve(_this2.dao.loadFilteredData(filters, st, lm)).then(function (filteredData) {
                response.data = filteredData;
                _exit = 1;
                return response;
              });
            }
          }();

          return _temp && _temp.then ? _temp.then(_temp2) : _temp2(_temp);
        });
      } catch (e) {
        return Promise.reject(e);
      }
    }
    /**
     * Obtencion de un elemento mediante su identificador
     */
    ;

    _proto.loadById = function loadById(id) {
      return this.dao.loadById(id);
    }
    /**
     * Metodo de creacion.
     *
     * Si el identificador se pasa como undefined se creara un nuevo elemento,
     * sino se modifica el correspondiente.
     */
    ;

    _proto.save = function save(data) {
      //Create
      return this.dao.save(data);
    }
    /**
     * Metodo de creacion.
     *
     * Si el identificador se pasa como undefined se creara un nuevo elemento,
     * sino se modifica el correspondiente.
     */
    ;

    _proto.update = function update(id, data) {
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
    ;

    _proto["delete"] = function _delete(id) {
      if (id) {
        return this.dao["delete"](id);
      }
    };

    return BaseService;
  }();

  function Runtime() {
    var optimist = _optimist__default["default"].usage("Como usar: \n node execute.js [--generateKeys , --encrypt xxx] \n\n Opciones:\n --generateKeys: Genera unas claves para la aplicación\n --encrypt String: Codifica el String proporcionado en base a la contraseña de .env \n\n ---> Si no se especifican parámetros el servidor arrancará normalmente.");

    var argv = optimist.argv; //Parámetro para no arrancar el servidor y generar las claves JWT

    if (argv.generateKeys) {
      console.log("Generando claves para encriptación:");
      console.log(Utils.generateKeys());
      return process.exit(1);
    }

    if (argv.encrypt) {
      console.log("Resultado encryptación:");
      console.log(Utils.encrypt(argv.encrypt));
      return process.exit(1);
    }

    if (argv.h || argv.help) {
      console.log(optimist.help());
      return process.exit(1);
    }
  }

  var App = /*#__PURE__*/function () {
    function App() {
      this.serverClass = Server;
      this.clusterClass = ClusterServer;
    }
    /**
     * Inicializa la runtime de la aplicación para poder recibir parámetros por consola y generar claves.
     * @returns
     */


    var _proto = App.prototype;

    _proto.runtime = function runtime() {
      return Runtime();
    }
    /**
     * Initializa las configuraciones para la app
     *
     */
    ;

    _proto.init = function init(serverConfig) {
      try {
        var _temp3 = function _temp3() {
          //Instanciar la clase server
          var server = new _this2.serverClass(serverConfig, _this2.statics, _this2.routes);

          if (_this2.customizeExpress) {
            server.customizeExpress = _this2.customizeExpress;
          }

          if (_this2.beforeListen) {
            server.beforeListen = _this2.beforeListen;
          }

          if (_this2.afterListen) {
            server.afterListen = _this2.afterListen;
          }
          /**
           * Gestor de eventos
           * @type {EventHandler}
           * @public
           */


          _this2.events = new EventHandler(_this2);
          /**
           * Gestor de traducciones
           * @type {I18nLoader}
           * @public
           */

          _this2.i18n = new I18nLoader();
          return Promise.resolve(_this2.i18n.load()).then(function () {
            /**
             * Servidor actual
             * @type {ClusterServer}
             * @public
             */
            _this2.server = new _this2.clusterClass(_this2);

            _this2.server.setServerCls(server);

            _this2.server.executeOnlyMain = function () {
              if (_this2.executeOnlyMain) _this2.executeOnlyMain();

              if (process.env.REPL_ENABLED == "true") {
                _this2.startRepl();
              }
            };
          });
        };

        var _this2 = this;

        var _temp4 = function () {
          if (process.env.DISABLE_LOGGER != "true") {
            return Promise.resolve(Logger.configure()).then(function () {});
          }
        }();

        return Promise.resolve(_temp4 && _temp4.then ? _temp4.then(_temp3) : _temp3(_temp4));
      } catch (e) {
        return Promise.reject(e);
      }
    }
    /**
     * Ejecuta el servidor con la configuracion de #init()
     */
    ;

    _proto.start = function start() {
      try {
        var _this4 = this;

        if (!_this4.server) {
          throw new Error("Call init first");
        }

        return Promise.resolve(_this4.server.start()).then(function () {});
      } catch (e) {
        return Promise.reject(e);
      }
    }
    /**
     * Inicia el server replify para poder conectar terminales remotas
     *
     *
     * Para que arranque es necesario especificar REPL_ENABLED en el archivo .env
     */
    ;

    _proto.startRepl = function startRepl() {
      var _this5 = this;

      try {
        net__default["default"].createServer(function (socket) {
          var remote = repl__default["default"].start({
            prompt: "lisco::remote> ",
            input: socket,
            output: socket,
            terminal: true,
            useColors: true,
            preview: false
          });
          remote.context.app = _this5;
          remote.context.Utils = Utils;
          remote.context.db = KnexConnector$1.connection;
          remote.on("exit", socket.end.bind(socket));
        }).listen(process.env.REPL_PORT || 5001);
      } catch (e) {
        console.log("Remote REPL Conn: " + e);
      }

      console.log("Remote REPL started on port " + (process.env.REPL_PORT || 5001));
    };

    return App;
  }();

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

}));
//# sourceMappingURL=lisco.umd.js.map
