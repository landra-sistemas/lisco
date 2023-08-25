import { I18nLoader, Utils } from "./common/index.js";
import { EventHandler } from "./events/index.js";
import { ClusterServer, Server } from "./server/index.js";
import { Logger } from "./logger/index.js";

import net from "net";
import repl from "repl";
import { KnexConnector } from "./db/index.js";
import Runtime from "./common/Runtime.js";

class App {
    constructor() {
        this.serverClass = Server;
        this.clusterClass = ClusterServer;
    }

    /**
     * Inicializa la runtime de la aplicación para poder recibir parámetros por consola y generar claves.
     * @returns
     */
    runtime(extra) {
        return Runtime(extra);
    }

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

        /**
         * Gestor de eventos
         * @type {EventHandler}
         * @public
         */
        this.events = new EventHandler(this);

        /**
         * Gestor de traducciones
         * @type {I18nLoader}
         * @public
         */
        this.i18n = new I18nLoader(serverConfig?.disableI18nWatcher);
        await this.i18n.load();
        /**
         * Servidor actual
         * @type {ClusterServer}
         * @public
         */
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
            net.createServer((socket) => {
                const remote = repl.start({
                    prompt: "lisco::remote> ",
                    input: socket,
                    output: socket,
                    terminal: true,
                    useColors: true,
                    preview: false,
                });
                remote.context.app = this;
                remote.context.Utils = Utils;
                remote.context.db = KnexConnector.connection;
                remote.on("exit", socket.end.bind(socket));
            }).listen(process.env.REPL_PORT || 5001);
        } catch (e) {
            console.log("Remote REPL Conn: " + e);
        }

        console.log(`Remote REPL started on port ${process.env.REPL_PORT || 5001}`);
    }
}

export default new App();
