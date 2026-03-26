import { expect } from "chai";
import { ClusterServer } from "../../src/index.js";

describe("ClusterServer", async () => {
    it("#normalizePort()", () => {
        const clusterServer = new ClusterServer({});

        expect(clusterServer.normalizePort("3000")).to.eq(3000);
        expect(clusterServer.normalizePort("pipe")).to.eq("pipe");
        expect(clusterServer.normalizePort("-1")).to.eq(false);
    });

    it("#start.unclustered()", async () => {
        const clusterServer = new ClusterServer({});
        clusterServer.clustered = "false";

        let executedMain = false;
        let initialized = false;

        clusterServer.executeOnlyMain = () => {
            executedMain = true;
        };
        clusterServer.initUnclustered = async () => {
            initialized = true;
        };

        await clusterServer.start();

        expect(executedMain).to.eq(true);
        expect(initialized).to.eq(true);
    });

    it("#start.clustered()", async () => {
        const clusterServer = new ClusterServer({});
        clusterServer.clustered = "true";

        let initialized = false;
        clusterServer.initClustered = () => {
            initialized = true;
        };

        await clusterServer.start();

        expect(initialized).to.eq(true);
    });

    it("#start.clustered.noExecuteOnlyMain()", async () => {
        const clusterServer = new ClusterServer({});
        clusterServer.clustered = "true";

        let initialized = false;
        let executedMain = false;

        clusterServer.initClustered = () => {
            initialized = true;
        };
        clusterServer.executeOnlyMain = () => {
            executedMain = true;
        };

        await clusterServer.start();

        expect(initialized).to.eq(true);
        expect(executedMain).to.eq(false);
    });

    it("#configureSocketIO.disabled()", () => {
        const app = {};
        const clusterServer = new ClusterServer(app);

        clusterServer.server = {
            express_config: {
                socketio: false,
            },
        };

        clusterServer.configureSocketIO({});

        expect(app.io).to.eq(undefined);
    });

    it("#handleErrors.nonListen()", () => {
        const clusterServer = new ClusterServer({});
        const error = { syscall: "other", code: "EACCES" };

        expect(() => clusterServer.handleErrors(error, 3000)).to.throw();
    });

    it("#handleErrors.EACCES()", () => {
        const clusterServer = new ClusterServer({});
        const originalExit = process.exit;
        let exitCode = null;

        try {
            process.exit = (code) => {
                exitCode = code;
                throw new Error("process.exit");
            };

            expect(() =>
                clusterServer.handleErrors({ syscall: "listen", code: "EACCES" }, 3000)
            ).to.throw("process.exit");

            expect(exitCode).to.eq(1);
        } finally {
            process.exit = originalExit;
        }
    });

    it("#handleErrors.EADDRINUSE()", () => {
        const clusterServer = new ClusterServer({});
        const originalExit = process.exit;
        let exitCode = null;

        try {
            process.exit = (code) => {
                exitCode = code;
                throw new Error("process.exit");
            };

            expect(() =>
                clusterServer.handleErrors({ syscall: "listen", code: "EADDRINUSE" }, 3000)
            ).to.throw("process.exit");

            expect(exitCode).to.eq(1);
        } finally {
            process.exit = originalExit;
        }
    });
});
