import { expect } from 'chai';
import cluster from 'cluster';
import { TokenGenerator } from '../src';


describe('TokenGenerator', () => {

    it('#sign()', async () => {
        const tokenGenerator = new TokenGenerator(process.env.JWT_SECRET, { audience: 'myaud', issuer: 'myissuer', subject: 'user', algorithm: process.env.JWT_ALGORITHM, expiresIn: process.env.JWT_EXPIRES })

        const token = tokenGenerator.sign({ myclaim: 'something' })

        console.log(token)


        expect(token).not.to.be.null;

    })

    it('#verify()', async () => {
        const tokenGenerator = new TokenGenerator(process.env.JWT_SECRET, { audience: 'myaud', issuer: 'myissuer', subject: 'user', algorithm: process.env.JWT_ALGORITHM, expiresIn: process.env.JWT_EXPIRES })
        const token = tokenGenerator.sign({ myclaim: 'something' })
        const payload = tokenGenerator.verify(token)

        console.log(payload)

        expect(payload).not.to.be.null;
        expect(payload).to.be.an("object");
        expect(payload).to.have.property('myclaim')
        expect(payload.myclaim).to.eq('something')

    })
    it('#refresh()', async () => {
        const tokenGenerator = new TokenGenerator(process.env.JWT_SECRET, { audience: 'myaud', issuer: 'myissuer', subject: 'user', algorithm: process.env.JWT_ALGORITHM, expiresIn: process.env.JWT_EXPIRES })
        const token = tokenGenerator.sign({ myclaim: 'something' })
        const refreshed = tokenGenerator.refresh(token)

        expect(refreshed).not.to.be.null;
        expect(refreshed).not.to.eq(token)

    })
    it('#fail.refresh()', async () => {
        try {
            const tokenGenerator = new TokenGenerator(process.env.JWT_SECRET, { audience: 'myaud', issuer: 'myissuer', subject: 'user', algorithm: process.env.JWT_ALGORITHM, expiresIn: process.env.JWT_EXPIRES })
            const refreshed = tokenGenerator.refresh("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")

        } catch (ex) {
            expect(ex).not.to.be.null;
        }

    })




})