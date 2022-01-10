import cluster from 'cluster';
import { EventEmitter } from 'events';
import ClusterMessages from 'cluster-messages';

/**
 * Clase encargada de la generacion de eventos.
 */
export default class EventHandler extends EventEmitter {

    constructor(app) {
        super();
        this.messages = new ClusterMessages();

        this.app = app; //Se recibe el singleton App para evitar referencias cruzadas

        if (cluster.isWorker) {
            // Levanto, en los worker, la escucha para recibir los eventos en broadcast de los demas hilos
            this.messages.on('event', (msg, callback) => {
                if (msg && msg.event && process.pid !== msg.props.owner) {
                    if (process.env.DEBUG_EVENTS == true) {
                        console.debug(`Receiving broadcast ${msg.event} - ${process.pid}`);
                    }
                    super.emit(msg.event, { ...msg.props }, callback);
                }
            });
        }
    }

    /**
     * Sobreescribir el emitter para notificar a los hijos
     * 
     * @param {*} evt 
     * @param {*} props 
     */
    emit(evt, props, callback) {
        //Desencadenar en local
        super.emit(evt, props, callback);

        if (evt && props && cluster.isWorker && process.pid !== props.owner) {
            if (process.env.DEBUG_EVENTS == true) {
                console.debug(`${evt} -> Firing from ${process.pid} to master`);
            }
            if (!props) {
                props = {};
            }
            props.owner = process.pid
            this.messages.send("event", { event: evt, props: { ...props } }, callback);
        }

        if (evt && props && cluster.isMaster && this.app && this.app.server && this.app.server.workers) {
            if (process.env.DEBUG_EVENTS == true) {
                console.debug(`${evt} -> Firing from master to workers`);
            }
            this.messages.send("event", { event: evt, props: { ...props } }, callback);
        }
    }
}
