import http from "http";
import https from "https";
import fs from "fs";
import path from "path";
import cluster from "cluster";
import { Server } from "socket.io";
import { setupMaster, setupWorker } from "@socket.io/sticky";
import { createAdapter, setupPrimary } from "@socket.io/cluster-adapter";
import os from "os";
import { EventEmitter } from "events";

import ClusterMessages from "cluster-messages";

/**
 * Inicializa la escucha del server en modo cluster
 */
export default class ClusterServer extends EventEmitter {
    constructor(app) {
        super();

        if (!process.env.PORT) {
            console.log("Using 3000 as default port. Customize via env PORT.");
        }
        this.port = this.normalizePort(process.env.PORT || 3000);
        this.clustered = process.env.CLUSTERED;
        this.workers = [];
        this.app = app;

        this.executeOnlyMain = () => {};
    }

    setServerCls(cls) {
        this.server = cls;
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
     * Inicializa el servidor de socketio en el puerto siguiente al configurado.
     *
     * Se puede desactivar mediante la config socketio: false al realizar el App.init()
     */
    configureSocketIO(server) {
        if (!this.server.express_config?.socketio) {
            return;
        }

        if (this.clustered !== "true") {
            this.server.io = new Server(this.server.express_config && this.server.express_config.socketio);
            this.server.io.listen(server);
            this.app.io = this.server.io;
            return;
        }

        if (this.clustered === "true") {
            if (cluster.isPrimary) {
                // setup sticky sessions
                setupMaster(server, {
                    loadBalancingMethod: "least-connection",
                });
                // setup connections between the workers
                setupPrimary();
                cluster.setupPrimary({
                    serialization: "advanced",
                });
            } else {
                this.server.io = new Server(this.server.express_config && this.server.express_config.socketio);
                this.server.io.listen(server);
                setupWorker(this.server.io);
                this.app.io = this.server.io;
            }
            return;
        }
    }

    /**
     * Inicializa la clase server encargada del control de las solicitudes en forma multiproceso.
     *
     */
    async initClustered() {
        //Launch cluster
        if (cluster.isPrimary) {
            this.executeOnlyMain();

            let messages = new ClusterMessages();
            messages.on("event", (msg, callback) => {
                if (msg && msg.event) {
                    if (process.env.DEBUG_EVENTS == true) {
                        console.debug(`Received '${msg.event}' from ${msg.props.owner} at Master`);
                    }
                    //Desencadenar en el proceso principal tambien
                    this.app.events.emit(msg.event, msg.props, callback);
                }
            });

            //Count the machine's CPUs
            const cpuCount = os.cpus().length;

            //Create a worker for each CPU
            for (let idx = 0; idx < cpuCount; idx += 1) {
                this.initWorker();
            }

            //Listen for dying workers
            cluster.on("exit", (worker) => {
                //Replace the dead worker, we're not sentimental
                console.log("Worker " + worker.id + " died :(");
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
        let worker = cluster.fork();
        console.log(`Running worker ${worker.process.pid}`);

        this.workers.push(worker);
    }

    /**
     * Inicializa la clase server encargada del control de las solicitudes en un unico proceso.
     *
     */
    async initUnclustered() {
        this.server.port = this.port;
        //create http server
        let server = http.Server(this.server.app);

        //Configure socketio if applies
        this.configureSocketIO(server);

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
            console.log("Server Worker running on port: " + this.port + "!");
            this.emit("listening", this.port);
        });

        if (process.env.SSL && process.env.SSL == "true") {
            if (!process.env.SSL_KEY || !process.env.SSL_CERT || !process.env.SSL_PASS) {
                console.error("Invalid SSL configuration. SLL_KEY, SSL_CERT and SSL_PASS needed");
                process.exit(0);
            }

            var key = fs.readFileSync(path.resolve(process.cwd(), process.env.SSL_KEY || "key.pem"));
            var cert = fs.readFileSync(path.resolve(process.cwd(), process.env.SSL_CERT || "cert.pem"));

            var options = {
                key: key,
                cert: cert,
                passphrase: process.env.SSL_PASS,
            };

            if (!process.env.SSL_PORT) {
                console.log("Using 3443 as ssl default port. Customize via env SSL_PORT.");
            }
            var sslPort = this.normalizePort(process.env.SSL_PORT || 3443);
            var serverSsl = https.createServer(options, this.server.app);
            serverSsl.listen(sslPort);
            //add error handler
            serverSsl.on("error", (err) => {
                this.handleErrors(err, sslPort);
            });
            //start listening on port
            serverSsl.on("listening", () => {
                console.log("Server Worker running on port: " + sslPort + "!");
                this.emit("listening_ssl", sslPort);
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

        let bind = typeof port === "string" ? "Pipe " + port : "Port " + port;

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
