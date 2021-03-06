import { expect } from 'chai';
import { JwtAuthHandler } from '../src';

const UserDao = {
    findByUsername: () => ({ username: "admin", password: "ee7646601f245dc9d098678949753e2e" })
}



describe('JwtAuthHandler', () => {


    it('#constructs()', async () => {
        try {
            const handler = new JwtAuthHandler();
        } catch (ex) {
            expect(ex).not.to.be.undefined;
        }
    })

    it('#check#invalid()', async () => {
        const handler = new JwtAuthHandler(UserDao);

        let result = await handler.check({ headers: { authorization: "" } });

        expect(result).not.to.be.null;
        expect(result).to.be.false;
    })

    it('#check#invalid2()', async () => {
        const handler = new JwtAuthHandler(UserDao);

        let result = await handler.check({ headers: { authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjE1MDQ0MTc3LCJleHAiOjE2MTUyMTY5NzcsImF1ZCI6Ik15QXVkaWVuY2UiLCJpc3MiOiJMYW5kcmEgU2lzdGVtYXMiLCJzdWIiOiJNeVN1YiIsImp0aSI6IjI0YjY1OWE0LTY1MTMtNDc5NC1iZWM2LTA3NWU1OTJiZTYxNiJ9.0GGDZ4EN1Qm9Q-tKfFFgvoQPMaKq0rn8DACxCombeEw" } });

        expect(result).not.to.be.null;
        //expect(result).to.be.false; //TODO cuando el token caduque descomentar esto
    })

    it('#check#valid()', async () => {
        const handler = new JwtAuthHandler(UserDao);

        let token = await handler.validate({}, "admin", "admin");
        let result = handler.check({ headers: { authorization: "Bearer " + token } });

        expect(result).not.to.be.null;
        expect(result).not.to.be.false;
    })


    it('#validate()', async () => {
        const handler = new JwtAuthHandler(UserDao);

        let result = await handler.validate({}, "admin", "admin");

        expect(result).not.to.be.null;
    })



})