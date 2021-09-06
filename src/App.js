import { I18nLoader, Utils } from "./common";
import { EventHandler } from "./events";
import { ClusterServer, Server } from "./server";
import { Logger } from "./logger";

import net from 'net';
import repl from 'repl';

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
        }
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
                    preview: false
                });
                remote.context.app = this;
                remote.context.Utils = Utils;
                remote.on('exit', socket.end.bind(socket))
            }).listen(process.env.REPL_PORT || 5001);
        } catch (e) {
            console.log("Remote REPL Conn: " + e);
        }

        console.log(`Remote REPL started on port ${(process.env.REPL_PORT || 5001)}`);

    }
}

export default new App();