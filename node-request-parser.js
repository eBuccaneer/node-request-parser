var _isFunction = require('lodash.isfunction'),
    _isArray = require('lodash.isarray'),
    _forEach = require('lodash.foreach'),
    sanitize,
    alwaysParse,
    authFunction;


function RequestParser(options) {
    if(options){
        /**
         * a sanitize function
         */
        sanitize = _isFunction(options.sanitizeFunction) ? options.sanitizeFunction : undefined;

        /**
         * an array of strings according to the specification of node-request-parser,
         * that are always parsed from a request
         */
        alwaysParse = _isArray(options.alwaysParse) ? options.alwaysParse : [];

        /**
         * has to be a function that requires request headers and callback(err, user) and then returns user
         * object(or every object you like extracted from the headers) like getUserFromRequest(headers, callback)
         */
        authFunction = _isFunction(options.authFunction) ? options.authFunction : undefined;
    } else {
        sanitize = undefined;
        alwaysParse = [];
        authFunction = undefined;
    }
}

/**
 * the actual parsing method
 */
RequestParser.prototype.parse = function (req, neededData, callback) {
    try{
        if (!_isArray(neededData)) return callback('neededData_no_array', null);
        var needed = alwaysParse.concat(neededData);
        if (needed.length <= 0) return callback('neededData_size_zero', null);

        var data = {
            body : {},
            params: {},
            headers: {},
            query: {},
            authorization: undefined
        };

        var errors = [];
        var specialError;
        var authOptional;
        var authorizationNeeded = false;

        _forEach(needed, function(key) {
            var isOptional = false;
            var body = false;
            var params = false;
            var headers = false;
            var query = false;
            var authFlag = false;
            var sanitized = false;

            if(key.startsWith('B')){
                body = true;
            }
            if(key.startsWith('P')){
                params = true;
            }
            if(key.startsWith('H')){
                headers = true;
            }
            if(key.startsWith('Q')){
                query = true;
            }
            if(key.startsWith('A')){
                authorizationNeeded = true;
                authFlag = true;
                if (key.endsWith('?')) {
                    authOptional = true;
                    key = key.slice(0, -1);
                }
            }

            key = key.slice(1);

            if(key.startsWith('*')){
                if(sanitize) {
                    sanitized = true;
                    key = key.slice(1);
                } else {
                    specialError = 'sanitizeFunction_not_set';
                }
            }

            if(key.endsWith('?')){
                isOptional = true;
                key = key.slice(0, -1);
            }

            if(body){
                if(req.body[key] !== undefined) {
                    if(typeof req.body[key] === 'number' || typeof req.body[key] === 'boolean'){
                        data.body[key] = req.body[key];
                    } else{
                        data.body[key] = sanitized ? sanitize(req.body[key]) : req.body[key];
                    }
                } else{
                    if(!isOptional) errors.push('body_missing_' + key);
                }
            } else if(params){
                if(req.params[key] !== undefined) {
                    if(typeof req.params[key] === 'number' || typeof req.params[key] === 'boolean'){
                        data.params[key] = req.params[key];
                    } else{
                        data.params[key] = sanitized ? sanitize(req.params[key]) : req.params[key];
                    }
                } else {
                    if(!isOptional) errors.push('params_missing_' + key);
                }
            } else if(headers){
                if(req.headers[key] !== undefined) {
                    if(typeof req.headers[key] === 'number' || typeof req.headers[key] === 'boolean'){
                        data.headers[key] = req.headers[key];
                    } else{
                        data.headers[key] = sanitized ? sanitize(req.headers[key]) : req.headers[key];
                    }
                } else {
                    if(!isOptional) errors.push('headers_missing_' + key);
                }
            } else if(query){
                if(req.query[key] !== undefined) {
                    if(typeof req.query[key] === 'number' || typeof req.query[key] === 'boolean'){
                        data.query[key] = req.query[key];
                    } else{
                        data.query[key] = sanitized ? sanitize(req.query[key]) : req.query[key];
                    }
                } else {
                    if(!isOptional) errors.push('query_missing_' + key);
                }
            } else if(authFlag){

            } else{
                errors.push('incorrectKey_' + key);
            }
        });

        if(specialError){
            return callback(specialError, null);
        } else if(errors.length > 0){
            return callback('parser_error', errors);
        }  else{
            if(authorizationNeeded) {
                if(!authFunction) return callback('authFunction_not_set', null);
                authFunction(req.headers, function (err, user) {
                    if (err || !user) {
                        if (authOptional) {
                            return callback(null, data);
                        } else {
                            return callback(err, null);
                        }
                    } else {
                        data.authorization = user;
                        return callback(null, data);
                    }
                });
            } else {
                return callback(null, data);
            }
        }


    } catch(err){
        return callback(err, null);
    }
};


module.exports = RequestParser;