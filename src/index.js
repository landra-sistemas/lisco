import { ClusterServer, Server, loadRoutes } from './server'
import { EventHandler } from './events'
import { Logger } from './logger'
import { I18nLoader, JsonResponse, Utils, TokenGenerator } from './common'
import { AuthController, JwtAuthHandler, IAuthHandler } from './auth'
import { KnexFilterParser, BaseKnexDao, KnexConnector, IUserDao } from './db'

const run_lisco = async (server) => {
    //Gestor de eventos
    const events = EventHandler; //Init singleton
    //Carga de utilidades
    await I18nLoader.load();
    //Inicio del cluster server
    ClusterServer.setServerCls(server);
}


export {
    run_lisco,
    ClusterServer,
    Server,
    loadRoutes,
    Logger,
    I18nLoader,
    JsonResponse,
    EventHandler,
    Utils,
    KnexConnector,
    TokenGenerator,
    AuthController,
    JwtAuthHandler,
    IAuthHandler,
    KnexFilterParser,
    BaseKnexDao,
    IUserDao
}
