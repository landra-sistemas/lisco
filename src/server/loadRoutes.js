/**
 * Instancia la lista de rutas disponibles
 * @param apps
 * @returns {*}
 */
const loadRoutes = (app, routes) => {
    if (!routes) return;

    for (const route of routes) {
        if (!route) continue;
        //TODO traze?
        const router = route.configure();
        if (router) {
            app.use(router);
        }
    }

};
export { loadRoutes };