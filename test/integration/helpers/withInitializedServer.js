import http from "http";
import { Server } from "../../../src/index.js";

export async function withInitializedServer(config, routes, testFn) {
    const server = new Server(config, null, routes);
    await server.initialize();

    const httpServer = http.createServer(server.app);
    await new Promise((resolve) => httpServer.listen(0, resolve));

    const { port } = httpServer.address();
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
        await testFn(baseUrl);
    } finally {
        await new Promise((resolve) => httpServer.close(resolve));
    }
}
