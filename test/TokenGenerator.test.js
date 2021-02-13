import { expect } from 'chai';
import cluster from 'cluster';
import { TokenGenerator } from '../src';


describe('TokenGenerator', () => {

    it('#sign()', async () => {
        const tokenGenerator = new TokenGenerator(process.env.JWT_SECRET, { algorithm: process.env.JWT_ALGORITHM, keyid: '1', expiresIn: process.env.JWT_EXPIRES })

        const token = tokenGenerator.sign({ myclaim: 'something' }, { audience: 'myaud', issuer: 'myissuer', jwtid: 1, subject: 'user' })

        console.log(token)

    })




})