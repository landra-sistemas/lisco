import cluster from 'cluster';
import { EventEmitter } from 'events';

/**
 * Clase encargada de la generacion de eventos.
 */
export default class EventHandler extends EventEmitter {

    constructor() {
        super();

        if (cluster.isWorker) {
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

        if (evt && props && cluster.isWorker) {
            console.debug(`${evt} -> Firing from ${process.pid} to master`);
            if (!props) {
                props = {};
            }
            props.owner = process.pid
            process.send({ event: evt, props });
        }

        if (evt && props && cluster.isMaster && global.cluster_server) {
            console.debug(`${evt} -> Firing from master to workers`);
            for (var i in global.cluster_server.workers) { //Si se recibe un evento del master
                //Se notifica a todos los demas workers excepto al que lo ha generado
                var current = global.cluster_server.workers[i];
                if (props && current.process.pid !== props.owner) {
                    console.debug(`${evt} -> Sending to ${current.process.pid}`)
                    current.send({ event: evt, props });
                }
            }
        }
    }
}