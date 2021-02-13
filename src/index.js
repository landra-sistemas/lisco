import { ClusterServer, Server } from './server'
import { EventHandler } from './events'
import { Logger } from './logger'
import { I18nLoader, JsonResponse, Utils, TokenGenerator } from './common'

const init_lisco = async (server) => {
    //Gestor de eventos
    global.events = new EventHandler();
    //Carga de utilidades
    global.i18n = new I18nLoader();
    await global.i18n.load();
    //Carga de utilidades
    global.utils = Utils;
    //Inicio del cluster server
    global.cluster_server = new ClusterServer(server);
}

export {
    init_lisco,
    ClusterServer,
    Server,
    Logger,
    I18nLoader,
    JsonResponse,
    EventHandler,
    Utils,
    TokenGenerator
}
