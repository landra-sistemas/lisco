import helmet from 'helmet';
import bodyParser from 'body-parser';
import express from 'express';
import compression from 'compression';
import cors from 'cors';
import fileUpload from 'express-fileupload';
import url from 'url';
import { JsonResponse } from '../common';

import { loadRoutes } from './loadRoutes'

/**
 * Clase servidor encargada de configurar las rutas.
 *
 * que el codigo se disperse entre diferentes proyectos.
 */
export default class Server {

    constructor(statics, routes) {
        this.app = express();
        this.statics = statics;
        this.routes = routes;
    }

    /**
     * Inicializa el servidor
     * @param {*} statics 
     * @param {*} routes 
     */
    initialize() {
        this.config(this.statics);
        if (this.customizeExpress) {
            this.customizeExpress()
        }
        this.configureRoutes(this.routes);
        this.errorHandler();
    }

    /**
     * Funcion sobreescribible para personalizar los componentes cargados en Express
     */
    customizeExpress() { }

    /**
     * Se encarga de realizar la configuración inicial del servidor
     * 
     * statics = {
     *     "/temp": "/temp"
     * }
     */
    config(statics) {

        //Security
        this.app.use(helmet());
        //mount json form parser
        this.app.use(bodyParser.json({ limit: '100mb' }));
        //mount query string parser
        this.app.use(bodyParser.urlencoded({ extended: true }));
        // compress responses
        this.app.use(compression());
        //Enable cors to allow external references
        this.app.options('*', cors({ origin: true, credentials: true }));
        this.app.use(cors({ origin: true, credentials: true }));

        // upload middleware
        this.app.use(fileUpload());

        //add static paths
        for (const idx in statics) {
            this.app.use(idx, express.static(statics[idx]));
        }

        //Logging
        this.app.use((request, response, next) => {
            request.requestTime = Date.now();
            response.on("finish", () => {
                let pathname = url.parse(request.url).pathname;
                let end = Date.now() - request.requestTime;
                let user = (request && request.session && request.session.user_id) || "";
                if (this.withLog) {
                    console.debug('APIRequest[' + process.pid + ']::. [' + request.method + '] (user:' + user + ')  ' + pathname + ' |-> took: ' + end + ' ms');
                    console.debug(JSON.stringify(request.body));
                }
            });
            next();
        });
    }

    /**
     * Crea el cargador automatico de rutas
     */
    configureRoutes(routes) {
        const router = express.Router();
        this.app.use(router);

        //create controllers
        loadRoutes(this.app, routes)
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
            if (this.withLog)
                console.error(err);

            res.status(500).json(jsRes.toJson());
        });
    }
}
