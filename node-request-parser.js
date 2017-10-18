var _isFunction = require('lodash.isfunction'),
    _isArray = require('lodash.isarray'),
    _forEach = require('lodash.foreach'),
    sanitize,
    alwaysParse,
    authFunction,
    excludeSanitizeTypes,
    regex = /^(^[ABHPQ])([*]?)([A-Za-z0-9_-]{0,100})([?]?)$/,
    srcTypes = { BODY: 0, HEADERS: 1, PARAMS: 2, QUERY: 3, AUTH: 4 };

/**
 * RequestParser object
 */
function RequestParser(options) {
    if (options) {
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

        /**
         * an array of strings, which js types to exclude from sanitizing generally
         */
        excludeSanitizeTypes = _isArray(options.excludeSanitizeTypes) ? options.excludeSanitizeTypes : ['boolean', 'number'];
    } else {
        sanitize = undefined;
        alwaysParse = [];
        authFunction = undefined;
        excludeSanitizeTypes = ['boolean', 'number'];
    }
}

/**
 * extract property from request
 */
extract = function (src, key, sanitized, isOptional) {
    if (!src) return 'extract_error';
    if (src[key] !== undefined) {
        if (excludeSanitizeTypes.indexOf((typeof src[key])) != -1) {
            return src[key];
        } else {
            return sanitized ? sanitize(src[key]) : src[key];
        }
    } else {
        if (!isOptional) return 'extract_error';
        return undefined;
    }
};

/**
 * check user input
 */
checkInput = function (req, neededData) {
    if (!_isArray(neededData)) return 'neededData_no_array';
    if (!req) return 'no_request_object';
    if (neededData.length <= 0 && alwaysParse.length <= 0) return 'neededData_size_zero';
    var regexError;
    _forEach(neededData, function (key) {
        if (key.match(regex) === null) {
            regexError = 'regex_error_' + key;
            return false;
        }
    });
    return regexError ? regexError : undefined;
};

/**
 * apply auth function
 */
parseAuth = function (headers, authOptional, callback) {
    authFunction(headers, function (err, user) {
        if (err || !user) {
            if (err) return callback(err, null);
            if (authOptional) return callback(null, undefined);
            return callback('no_parsed_user_error', null);
        } else {
            return callback(null, user);
        }
    });
};


/**
 * the sync parsing method
 */
RequestParser.prototype.parseSync = function (req, neededData) {
    try {
        var inputError = checkInput(req, neededData);
        if (inputError) return {error: inputError};

        var needed = alwaysParse.concat(neededData);

        var data = {
            body: {},
            params: {},
            headers: {},
            query: {},
            authorization: undefined
        };

        var errors = [];
        var error;

        _forEach(needed, function (key) {
            var isOptional = false;
            var body = false;
            var params = false;
            var headers = false;
            var query = false;
            var sanitized = false;

            if (key.startsWith('B')) {
                body = true;
            }
            if (key.startsWith('P')) {
                params = true;
            }
            if (key.startsWith('H')) {
                headers = true;
            }
            if (key.startsWith('Q')) {
                query = true;
            }
            if (key.startsWith('A')) {
                error = 'sync_auth_not_possible';
                return false;
            }

            key = key.slice(1);

            if (key.startsWith('*')) {
                if (sanitize) {
                    sanitized = true;
                    key = key.slice(1);
                } else {
                    error = 'sanitizeFunction_not_set';
                    return false;
                }
            }

            if (key.endsWith('?')) {
                isOptional = true;
                key = key.slice(0, -1);
            }

            if (body) {
                data.body[key] = extract(req.body, key, sanitized, isOptional);
                if (data.body[key] === 'extract_error') errors.push('body_missing_' + key);
            } else if (params) {
                data.params[key] = extract(req.params, key, sanitized, isOptional);
                if (data.params[key] === 'extract_error') errors.push('params_missing_' + key);
            } else if (headers) {
                data.headers[key] = extract(req.headers, key, sanitized, isOptional);
                if (data.headers[key] === 'extract_error') errors.push('headers_missing_' + key);
            } else if (query) {
                data.query[key] = extract(req.query, key, sanitized, isOptional);
                if (data.query[key] === 'extract_error') errors.push('query_missing_' + key);
            } else {
                errors.push('incorrectKey_' + key);
            }
        });

        if (error) {
            return {error: error};
        } else if (errors.length > 0) {
            return {error: 'parser_error', errors: errors};
        } else {
            return data;
        }


    } catch (err) {
        return err;
    }
};


/**
 * the async parsing method
 */
RequestParser.prototype.parse = function (req, neededData, callback) {
    try {
        var inputError = checkInput(req, neededData);
        if (inputError) return callback(inputError, null);

        var needed = alwaysParse.concat(neededData);

        var data = {
            body: {},
            params: {},
            headers: {},
            query: {},
            authorization: undefined
        };

        var errors = [];
        var error;
        var authOptional;
        var authorizationNeeded = false;

        _forEach(needed, function (key) {

            var isOptional = false;
            var body = false;
            var params = false;
            var headers = false;
            var query = false;
            var sanitized = false;

            if (key.startsWith('B')) {
                body = true;
            }
            if (key.startsWith('P')) {
                params = true;
            }
            if (key.startsWith('H')) {
                headers = true;
            }
            if (key.startsWith('Q')) {
                query = true;
            }
            if (key.startsWith('A')) {
                if (!authFunction) {
                    error = 'authFunction_not_set';
                    return false;
                }
                authorizationNeeded = true;
                if (key.endsWith('?')) {
                    authOptional = true;
                }
                return;
            }

            key = key.slice(1);

            if (key.startsWith('*')) {
                if (sanitize) {
                    sanitized = true;
                    key = key.slice(1);
                } else {
                    error = 'sanitizeFunction_not_set';
                    return false;
                }
            }

            if (key.endsWith('?')) {
                isOptional = true;
                key = key.slice(0, -1);
            }

            if (body) {
                data.body[key] = extract(req.body, key, sanitized, isOptional);
                if (data.body[key] === 'extract_error') errors.push('body_missing_' + key);
            } else if (params) {
                data.params[key] = extract(req.params, key, sanitized, isOptional);
                if (data.params[key] === 'extract_error') errors.push('params_missing_' + key);
            } else if (headers) {
                data.headers[key] = extract(req.headers, key, sanitized, isOptional);
                if (data.headers[key] === 'extract_error') errors.push('headers_missing_' + key);
            } else if (query) {
                data.query[key] = extract(req.query, key, sanitized, isOptional);
                if (data.query[key] === 'extract_error') errors.push('query_missing_' + key);
            } else {
                errors.push('incorrectKey_' + key);
            }
        });

        if (error) {
            return callback(error, null);
        } else if (errors.length > 0) {
            return callback('parser_error', errors);
        } else {
            if (authorizationNeeded) {
                parseAuth(req.headers, authOptional, function (err, user) {
                    if (err) return callback(err, null);
                    data.authorization = user;
                    return callback(null, data);
                });
            } else {
                return callback(null, data);
            }
        }
    } catch (err) {
        return callback(err, null);
    }
};


module.exports = RequestParser;