import { expect } from "chai";
import express from "express";
import { withInitializedServer } from "./helpers/withInitializedServer.js";

describe("Server integration", () => {
    it("serves routes under configured prefix", async () => {
        const routes = [
            {
                configure: () => {
                    const router = express.Router();
                    router.get("/ping", (_req, res) => res.status(200).json({ ok: true }));
                    return router;
                },
            },
        ];

        await withInitializedServer(
            {
                prefix: "/api",
                helmet: false,
                json: false,
                urlencoded: false,
                compression: false,
                cors: false,
                fileupload: false,
            },
            routes,
            async (baseUrl) => {
                const response = await fetch(`${baseUrl}/api/ping`);
                const body = await response.json();

                expect(response.status).to.eq(200);
                expect(body.ok).to.eq(true);
            }
        );
    });

    it("supports legacy wildcard shorthand routes in Express 5", async () => {
        const routes = [
            {
                configure: () => express.Router(),
                routes: {
                    "*": {
                        get: (_req, res) => {
                            res.status(200).json({ matched: true });
                        },
                    },
                },
            },
        ];

        await withInitializedServer(
            {
                helmet: false,
                json: false,
                urlencoded: false,
                compression: false,
                cors: false,
                fileupload: false,
            },
            routes,
            async (baseUrl) => {
                const response = await fetch(`${baseUrl}/any/path`);
                const body = await response.json();

                expect(response.status).to.eq(200);
                expect(body.matched).to.eq(true);
            }
        );
    });

    it("returns JsonResponse on async route errors", async () => {
        const routes = [
            {
                configure: () => express.Router(),
                routes: {
                    "/boom": {
                        get: async () => {
                            throw new Error("boom");
                        },
                    },
                },
            },
        ];

        await withInitializedServer(
            {
                helmet: false,
                json: false,
                urlencoded: false,
                compression: false,
                cors: false,
                fileupload: false,
            },
            routes,
            async (baseUrl) => {
                const response = await fetch(`${baseUrl}/boom`);
                const body = await response.json();

                expect(response.status).to.eq(500);
                expect(body.success).to.eq(false);
                expect(body.message).to.eq("boom");
            }
        );
    });

    it("returns 404 for unknown routes", async () => {
        await withInitializedServer(
            {
                helmet: false,
                json: false,
                urlencoded: false,
                compression: false,
                cors: false,
                fileupload: false,
            },
            [],
            async (baseUrl) => {
                const response = await fetch(`${baseUrl}/does-not-exist`);
                expect(response.status).to.eq(404);
            }
        );
    });

    it("handles global CORS preflight", async () => {
        await withInitializedServer(
            {
                helmet: false,
                json: false,
                urlencoded: false,
                compression: false,
                cors: { origin: true, credentials: true },
                fileupload: false,
            },
            [],
            async (baseUrl) => {
                const response = await fetch(`${baseUrl}/cors-check`, {
                    method: "OPTIONS",
                    headers: {
                        Origin: "http://example.com",
                        "Access-Control-Request-Method": "GET",
                    },
                });

                expect(response.status).to.eq(204);
                expect(response.headers.get("access-control-allow-origin")).to.eq("http://example.com");
            }
        );
    });

    it("serves shorthand routes under configured prefix", async () => {
        const routes = [
            {
                configure: () => express.Router(),
                routes: {
                    "/status": {
                        get: (_req, res) => res.status(200).json({ up: true }),
                    },
                },
            },
        ];

        await withInitializedServer(
            {
                prefix: "/api",
                helmet: false,
                json: false,
                urlencoded: false,
                compression: false,
                cors: false,
                fileupload: false,
            },
            routes,
            async (baseUrl) => {
                const response = await fetch(`${baseUrl}/api/status`);
                const body = await response.json();

                expect(response.status).to.eq(200);
                expect(body.up).to.eq(true);
            }
        );
    });
});
