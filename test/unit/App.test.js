import { expect } from "chai";
import { App } from "../../src/index.js";

describe("App", async () => {
    it("#App.init()", async () => {
        const originalServerClass = App.serverClass;
        const originalClusterClass = App.clusterClass;

        class FakeServer {
            constructor(config, statics, routes, ioroutes) {
                this.config = config;
                this.statics = statics;
                this.routes = routes;
                this.ioroutes = ioroutes;
            }
        }

        class FakeClusterServer {
            constructor(app) {
                this.app = app;
                this.serverCls = null;
            }

            setServerCls(cls) {
                this.serverCls = cls;
            }

            async start() {}
        }

        try {
            App.serverClass = FakeServer;
            App.clusterClass = FakeClusterServer;

            await App.init({ disableI18nWatcher: true });

            expect(App.server).not.to.be.null;
            expect(App.server).to.be.instanceOf(FakeClusterServer);
            expect(App.server.serverCls).to.be.instanceOf(FakeServer);
        } finally {
            App.serverClass = originalServerClass;
            App.clusterClass = originalClusterClass;
        }
    });

    it("#App.start()", async () => {
        const originalServer = App.server;
        let called = false;

        try {
            App.server = {
                start: async () => {
                    called = true;
                },
            };

            await App.start();
            expect(called).to.eq(true);
        } finally {
            App.server = originalServer;
        }
    });

    it("#App.start.withoutInit()", async () => {
        const originalServer = App.server;
        try {
            App.server = null;

            let error = null;
            try {
                await App.start();
            } catch (e) {
                error = e;
            }

            expect(error).not.to.be.null;
            expect(error.message).to.eq("Call init first");
        } finally {
            App.server = originalServer;
        }
    });

    it("#App.init.executeOnlyMain.withRepl()", async () => {
        const originalServerClass = App.serverClass;
        const originalClusterClass = App.clusterClass;
        const originalExecuteOnlyMain = App.executeOnlyMain;
        const originalStartRepl = App.startRepl;
        const originalReplEnabled = process.env.REPL_ENABLED;

        let mainCalled = false;
        let replCalled = false;

        class FakeServer {
            constructor(config, statics, routes, ioroutes) {
                this.config = config;
                this.statics = statics;
                this.routes = routes;
                this.ioroutes = ioroutes;
            }
        }

        class FakeClusterServer {
            constructor(app) {
                this.app = app;
            }

            setServerCls() {}

            async start() {}
        }

        try {
            App.serverClass = FakeServer;
            App.clusterClass = FakeClusterServer;
            App.executeOnlyMain = () => {
                mainCalled = true;
            };
            App.startRepl = () => {
                replCalled = true;
            };
            process.env.REPL_ENABLED = "true";

            await App.init({ disableI18nWatcher: true });
            App.server.executeOnlyMain();

            expect(mainCalled).to.eq(true);
            expect(replCalled).to.eq(true);
        } finally {
            App.serverClass = originalServerClass;
            App.clusterClass = originalClusterClass;
            App.executeOnlyMain = originalExecuteOnlyMain;
            App.startRepl = originalStartRepl;
            process.env.REPL_ENABLED = originalReplEnabled;
        }
    });
});
