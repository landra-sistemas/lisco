import helmet from "helmet";
import express from "express";
import compression from "compression";
import cors from "cors";
import fileUpload from "express-fileupload";
import url from "url";
import lodash from "lodash";
import { JsonResponse, Utils } from "../common/index.js";

/**
 * Clase servidor encargada de configurar las rutas.
 *
 * que el codigo se disperse entre diferentes proyectos.
 */
export default class Server {
    /**
     *
     * @param {*} config
     * @param {*} statics
     * @param {*} routes
     */
    constructor(config, statics, routes) {
        this.app = express();
        this.express_config = lodash.defaultsDeep(config, {
            helmet: true,
            json: true,
            urlencoded: true,
            compression: true,
            cors: { origin: true, credentials: true },
            fileupload: true,
            socketio: { transports: ["websocket"] },
            traceRequests: false,
            prefix: undefined,
        });
        this.statics = statics;
        this.routes = routes;
    }

    /**
     * Inicializa el servidor
     */
    async initialize() {
        this.config(this.express_config);
        if (this.customizeExpress) {
            await this.customizeExpress(this.app);
        }
        await this.configureRoutes(this.routes);
        await this.errorHandler();
    }

    /**
     * Funcion sobreescribible para personalizar los componentes cargados en Express
     *
     * Aqui se pueden poner cosas como:
     *
     * this.app.use(cookieParser())... etc
     */
    customizeExpress() {}

    /**
     * Se encarga de realizar la configuración inicial del servidor
     *
     */
    config(config) {
        if (config && config.helmet) {
            //Security
            this.app.use(helmet(config && lodash.isObject(config.helmet) ? config.helmet : undefined));
        }
        if (config && config.json) {
            //mount json form parser
            this.app.use(express.json());
        }

        if (config && config.urlencoded) {
            //mount query string parser
            this.app.use(express.urlencoded({ extended: true }));
        }
        if (config && config.compression) {
            // compress responses
            this.app.use(compression());
        }
        if (config && config.cors) {
            //Enable cors to allow external references
            this.app.options("*", cors(config && lodash.isObject(config.cors) && config.cors));
            this.app.use(cors(config && lodash.isObject(config.cors) && config.cors));
        }
        if (config && config.fileupload) {
            // upload middleware
            this.app.use(fileUpload());
        }

        if (this.statics) {
            //add static paths
            for (const idx in this.statics) {
                this.app.use(idx, express.static(this.statics[idx]));
            }
        }

        //Logging
        if (config && config.traceRequests === true && process.env.DISABLE_LOGGER != "true") {
            this.app.use((request, response, next) => {
                request.requestTime = Date.now();
                response.on("finish", () => {
                    let pathname = url.parse(request.url).pathname;
                    let end = Date.now() - request.requestTime;
                    let user = (request && request.session && request.session.user_id) || "";

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
    configureRoutes(routes) {
        const router = express.Router();
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
            if (!route) {
                console.warn("Empty route");
                continue;
            }
            let router = route.configure();

            //perform autoconfig for base api crud operations
            if (route.entity) {
                router = route.configure(route.entity, { service: route.service, table: route.table });
            }

            //load shorthand routes
            if (!lodash.isEmpty(route.routes)) {
                const exAsync = Utils.expressHandler();
                for (const path in route.routes) {
                    const cfg = route.routes[path];
                    for (const method in cfg) {
                        const handler = cfg[method];
                        if (Array.isArray(handler)) {
                            //Securización (keycloak)
                            router[method](path, handler[0], exAsync(handler[1]));
                        } else {
                            router[method](path, exAsync(handler));
                        }
                    }
                }
            }
            if (router && this.express_config?.prefix) {
                app.use(this.express_config?.prefix, router);
            } else if (router) {
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
            jsRes.message = err.message; //!FIXME protect error displaying in REST Responses
            console.error(err);

            res.status(500).json(jsRes.toJson());
        });
    }
}
