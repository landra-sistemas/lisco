class KnexConnector {

    init(config) {
        this.connection = require('knex')(config)
    }

}


export default new KnexConnector();