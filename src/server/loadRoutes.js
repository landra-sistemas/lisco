/**
 * Instancia la lista de rutas disponibles
 * @param apps
 * @returns {*}
 */
const loadRoutes = (app, routes) => {

    for (let idx in routes) {
        const controller = routes[idx];
        let route;
        try {
            route = new controller();
        } catch (ex) {
            console.error(`Error creating ${controller && controller.name}: ${ex}`);
        }
        if (!route) continue;

        const router = route.configure();
        if (router) {
            app.use(router);
        }
    }

};
export { loadRoutes };