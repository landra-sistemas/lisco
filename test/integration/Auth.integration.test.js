import { expect } from "chai";
import express from "express";
import { AuthController } from "../../src/index.js";
import { withInitializedServer } from "./helpers/withInitializedServer.js";

describe("Auth integration", () => {
    it("enforces public/private/login/logout flow", async () => {
        let logoutCalled = false;

        const authHandler = {
            async check(request) {
                return request.headers.authorization === "Bearer ok";
            },
            async validate(_request, username, password) {
                if (username === "admin" && password === "secret") {
                    return { username };
                }
                return false;
            },
            async logout() {
                logoutCalled = true;
                return true;
            },
        };

        const authController = new AuthController(["/public"], authHandler);

        const routes = [
            {
                configure: () => authController.configure(),
            },
            {
                configure: () => express.Router(),
                routes: {
                    "/public": {
                        get: (_req, res) => res.status(200).json({ public: true }),
                    },
                    "/private": {
                        get: (_req, res) => res.status(200).json({ private: true }),
                    },
                },
            },
        ];

        await withInitializedServer(
            {
                helmet: false,
                json: true,
                urlencoded: false,
                compression: false,
                cors: false,
                fileupload: false,
            },
            routes,
            async (baseUrl) => {
                const publicResponse = await fetch(`${baseUrl}/public`);
                const publicBody = await publicResponse.json();
                expect(publicResponse.status).to.eq(200);
                expect(publicBody.public).to.eq(true);

                const privateForbidden = await fetch(`${baseUrl}/private`);
                const privateForbiddenBody = await privateForbidden.json();
                expect(privateForbidden.status).to.eq(403);
                expect(privateForbiddenBody.success).to.eq(false);

                const privateAllowed = await fetch(`${baseUrl}/private`, {
                    headers: {
                        Authorization: "Bearer ok",
                    },
                });
                const privateAllowedBody = await privateAllowed.json();
                expect(privateAllowed.status).to.eq(200);
                expect(privateAllowedBody.private).to.eq(true);

                const loginInvalid = await fetch(`${baseUrl}/login`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({ username: "admin", password: "bad" }),
                });
                expect(loginInvalid.status).to.eq(401);

                const loginValid = await fetch(`${baseUrl}/login`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({ username: "admin", password: "secret" }),
                });
                const loginValidBody = await loginValid.json();
                expect(loginValid.status).to.eq(200);
                expect(loginValidBody.success).to.eq(true);
                expect(loginValidBody.data.username).to.eq("admin");

                const logoutResponse = await fetch(`${baseUrl}/logout`, {
                    method: "POST",
                    headers: {
                        Authorization: "Bearer ok",
                    },
                });
                const logoutBody = await logoutResponse.json();
                expect(logoutResponse.status).to.eq(200);
                expect(logoutBody.success).to.eq(true);
                expect(logoutCalled).to.eq(true);
            }
        );
    });
});
