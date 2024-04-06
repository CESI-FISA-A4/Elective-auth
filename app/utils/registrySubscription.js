const axios = require("axios");

module.exports = {
    subscribeToApiGateway: async() => {
        try {
            const response = await axios({
                method: "POST",
                baseURL: `http://${process.env.GATEWAY_HOST}:${process.env.GATEWAY_PORT}`,
                url: `/registry/services`,
                data: {
                    "serviceIdentifier": "auth-service",
                    "serviceLabel": "Service Auth",
                    "host": process.env.HOST,
                    "port": process.env.PORT,
                    "entrypointUrl": "/api/auth",
                    "redirectUrl": "/api/auth"
                }
            });
        } catch (error) {
            console.log(error);
        }
    }
}