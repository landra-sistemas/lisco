import http from 'http';
import https from 'https';
import fs from 'fs';
import path from 'path';
import cluster from 'cluster';
import socketio from 'socket.io';
import os from 'os'
import { EventEmitter } from 'events';

/**
 * Inicializa la escucha del server en modo cluster
 */
export default class ClusterServer extends EventEmitter {
    constructor(app) {
        super();

        if (!process.env.PORT) {
            console.log('Using 3000 as default port. Customize via env PORT.')
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
    start() {
        if (this.clustered == "true") {
            this.initClustered();
        } else {

            this.executeOnlyMain();
            this.initUnclustered();
        }
    }

    /**
     * Inicializa la clase server encargada del control de las solicitudes en forma multiproceso.
     *
     */
    initClustered() {
        //Launch cluster
        if (cluster.isMaster) {
            this.executeOnlyMain();
            //Count the machine's CPUs
            const cpuCount = os.cpus().length;

            //Create a worker for each CPU
            for (let idx = 0; idx < cpuCount; idx += 1) {
                this.initWorker();
            }

            //Listen for dying workers
            cluster.on('exit', (worker) => {

                //Replace the dead worker, we're not sentimental
                console.log('Worker ' + worker.id + ' died :(');
                this.initWorker();

            });
        } else {
            this.initUnclustered();

            console.log(`Worker ${process.pid} started`);
        }
    }
    /**
     * Inicia un worker
     */
    initWorker() {
        let worker = cluster.fork();
        console.log(`Running worker ${worker.process.pid}`)
        worker.on('message', (msg) => {
            if (msg.event) {
                console.debug(`Received ${msg.event} on ${worker.process.pid}`)
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
    initUnclustered() {
        //Initialize clustered servers
        this.server = this.cls;

        this.server.port = this.port;
        //create http server
        let server = http.Server(this.server.app);

        this.app.io = socketio(server);

        this.server.initialize();

        //listen on provided ports
        server.listen(this.server.port);

        //add error handler
        server.on("error", (err) => {
            this.handleErrors(err, this.server.port);
        });
        //start listening on port
        server.on("listening", () => {
            console.log('Server Worker running on port: ' + this.port + '!');
            this.emit('listening', this.port);
        });

        if (process.env.SSL && process.env.SSL == true) {
            if (!process.env.SSL_KEY || !process.env.SSL_CERT || !process.env.SSL_PASS) {
                console.error('Invalid SSL configuration. SLL_KEY, SSL_CERT and SSL_PASS needed');
                process.exit(0);
            }

            var key = fs.readFileSync(path.resolve(process.cwd(), process.env.SSL_KEY || 'key.pem'));
            var cert = fs.readFileSync(path.resolve(process.cwd(), process.env.SSL_CERT || 'cert.pem'));

            var options = {
                key: key,
                cert: cert,
                passphrase: process.env.SSL_PASS,
            };

            if (!process.env.SSL_PORT) {
                console.log('Using 3443 as ssl default port. Customize via env SSL_PORT.')
            }
            var sslPort = this.normalizePort(process.env.SSL_PORT || 3443);
            var serverSsl = https.createServer(options, this.server.app);
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