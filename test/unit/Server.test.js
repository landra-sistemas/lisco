import { expect } from "chai";
import { Server } from "../../src/index.js";

describe("Server", async () => {
    it("#constructs()", () => {
        const server = new Server();
        expect(server).not.to.be.null;
    });

    it("#initialize.order()", async () => {
        const calls = [];
        const server = new Server();

        server.config = () => {
            calls.push("config");
        };
        server.customizeExpress = async () => {
            calls.push("customizeExpress");
        };
        server.configureRoutes = async () => {
            calls.push("configureRoutes");
        };
        server.errorHandler = async () => {
            calls.push("errorHandler");
        };
        server.configureIoEvents = async () => {
            calls.push("configureIoEvents");
        };

        await server.initialize();

        expect(calls).to.deep.equal(["config", "customizeExpress", "configureRoutes", "errorHandler", "configureIoEvents"]);
    });
    it("#initializes()", () => {
        const statics = {
            "/temp": "/temp",
        };
        const server = new Server(statics, []);
        server.initialize();

        expect(server).not.to.be.null;
        expect(server.app).not.to.be.null;
        expect(server.app.statics).not.to.be.null;
        expect(server.statics).not.to.be.undefined;
    });
    it("#configures()", () => {
        const statics = {
            "/temp": "/temp",
        };
        const server = new Server();
        server.config(statics);

        expect(server).not.to.be.null;
        expect(server.app).not.to.be.null;
        expect(server.app.statics).not.to.be.null;
        expect(server.statics).to.be.undefined;
    });

    it("#configureRoutes()", () => {
        var tester;
        const route = {
            configure: () => {
                tester = "OK";
            },
        };
        const statics = {
            "/temp": "/temp",
        };
        const routes = [route];
        const server = new Server(statics, routes);
        server.configureRoutes(routes);

        expect(server).not.to.be.null;
        expect(server.app).not.to.be.null;
        expect(server.statics).not.to.be.null;
        expect(server.routes).not.to.be.null;
        expect(tester).not.to.be.null;
        expect(tester).to.eq("OK");
    });

    it("#emptyRoute.to.configureRoutes()", () => {
        var tester;
        const route = {
            configure: () => {
                tester = "OK";
                return () => {};
            },
        };
        const statics = {
            "/temp": "/temp",
        };
        const routes = [route, null];
        const server = new Server(statics, routes);
        server.configureRoutes(routes);

        expect(server).not.to.be.null;
        expect(server.app).not.to.be.null;
        expect(server.statics).not.to.be.null;
        expect(server.routes).not.to.be.null;
        expect(tester).not.to.be.null;
        expect(tester).to.eq("OK");
    });

    it("#configureIoEvents()", () => {
        const events = [];
        const handler = () => {};
        const server = new Server({}, null, [], { connected: handler });
        server.io = {
            on: (eventName, eventHandler) => {
                events.push({ eventName, eventHandler });
            },
        };

        server.configureIoEvents(server.ioevents);

        expect(events.length).to.eq(1);
        expect(events[0].eventName).to.eq("connected");
        expect(events[0].eventHandler).to.eq(handler);
    });

    it("#configureIoEvents#withoutEvents()", () => {
        const server = new Server({}, null, [], undefined);
        let called = false;
        server.io = {
            on: () => {
                called = true;
            },
        };

        server.configureIoEvents(server.ioevents);

        expect(called).to.eq(false);
    });

    it("#config#cors.express5()", () => {
        const server = new Server();

        server.config({
            cors: { origin: true, credentials: true },
            helmet: false,
            json: false,
            urlencoded: false,
            compression: false,
            fileupload: false,
        });

        expect(server.app).not.to.be.null;
    });

    it("#loadRoutes#legacyWildcardPath()", () => {
        const paths = [];
        const route = {
            routes: {
                "*": {
                    get: () => {},
                },
                "/*": {
                    get: () => {},
                },
            },
            configure: () => ({
                get: (path) => {
                    paths.push(path);
                },
            }),
        };

        const server = new Server();
        server.loadRoutes({ use: () => {} }, [route]);

        expect(paths.length).to.eq(2);
        expect(paths[0]).to.be.instanceOf(RegExp);
        expect(paths[1]).to.be.instanceOf(RegExp);
        expect(paths[0].test("/any/path")).to.eq(true);
        expect(paths[1].test("/any/path")).to.eq(true);
    });

    it("#errorHandler()", () => {
        const server = new Server();
        let errorMiddleware = null;

        server.app.use = (middleware) => {
            errorMiddleware = middleware;
        };

        server.errorHandler();

        let code = null;
        let payload = null;
        const response = {
            status: (statusCode) => {
                code = statusCode;
                return {
                    json: (jsonPayload) => {
                        payload = jsonPayload;
                    },
                };
            },
        };

        errorMiddleware(new Error("boom"), {}, response, () => {});

        expect(code).to.eq(500);
        expect(payload.success).to.eq(false);
        expect(payload.message).to.eq("boom");
    });

    // describe('#error()', () => {
    //     console.error('err');
    // })
});
