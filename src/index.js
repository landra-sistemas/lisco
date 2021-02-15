import { ClusterServer, Server, loadRoutes } from './server'
import { EventHandler } from './events'
import { Logger } from './logger'
import { I18nLoader, JsonResponse, Utils, TokenGenerator } from './common'
import { AuthController, JwtAuthHandler } from './auth'

const run_lisco = async (server) => {
    //Gestor de eventos
    global.events = new EventHandler();
    //Carga de utilidades
    global.i18n = new I18nLoader();
    await global.i18n.load();
    //Carga de utilidades
    global.utils = Utils;
    //Inicio del cluster server
    const test = new ClusterServer(server);
    global.cluster_server  = test;
}

/**
 * Initializes database connection
 * @param {*} config 
 */
const load_db = (config) => {
    if (config) {
        global.knex = require('knex')(config);
    }
}

export {
    run_lisco,
    load_db,
    ClusterServer,
    Server,
    loadRoutes,
    Logger,
    I18nLoader,
    JsonResponse,
    EventHandler,
    Utils,
    TokenGenerator,
    AuthController,
    JwtAuthHandler
}
