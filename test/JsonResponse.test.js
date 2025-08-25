import { expect } from "chai";
import { JsonResponse } from "../src/index.js";

describe("JsonResponse", () => {
    it("#create()", async () => {
        let response = new JsonResponse(true, []);

        expect(response).not.to.be.undefined;
    });

    it("#toJson()", async () => {
        let response = new JsonResponse(true, []);

        expect(response.toJson()).not.to.be.undefined;
    });
});
