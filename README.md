# node-request-parser

## Description
The module node-request-parser represents a parser for requests in node and express.
This parser is able to extract properties from the request object, sanitize them with
a given sanitizer function and return proper errors if the properties you expect are missing.
Additionally you can pass an authorization function that the parser uses to extract i.e.
a header property and map it to a user object. And all this is done with one single call!

## Install
Use NPM to install node-request-parser and add dependency to package.json:
```bash
$ npm install --save node-request-parser
```

## Usage
#### Initialize
```js
var RequestParser = require('node-request-parser');
//detailed description of options object down below
var options = {disableRegex: true};
var parser = new RequestParser(options);
```

#### Keys
Keys are used to specify what properties of the request you want to parse and how you want them.
Let me explain it with an example:

`'B*id?'`

This key means, you want a property from `request.body` that is named `id`, you want it to be
sanitized using your specified sanitizer function and you say it is optional, so no error is
returned if the property is missing.

So keys can be as follows:
* Starting with one of the following characters:
    * `B` for body
    * `P` for params
    * `H` for headers
    * `Q` for query
    * `A` for authorization
* an optional `*`, if given then the property is sanitized
* the name of the property you want to parse
* an optional `?` to mark the property as optional

If the key `A` or `A?` is used, there is no need to pass
`*` or a property name, only the given authFunction is executed.

#### Parsing async
Use i.e. in express route endpoints:
```js
router.get('/foo', function(req, res, next) {
    parser.parse(req, ['Bid'], function(err, data) {
        if(err){
            /*
            if an error occures and error === 'parser_error',
            then data is an array with more detailed errors like i.e.:
            data = ['body_missing_id']
            */
        } else{
            /*
            if everything is okay, the data object should look like:
            data = {
                body: {
                    id: 'theParsedId'
                }
            }
            */
        }
    });
});
```

#### Parsing sync
Use i.e. in express route endpoints:
```js
router.get('/foo', function(req, res, next) {
    var data = parser.parseSync(req, ['Bid']);
    if(data.error){
        /*
        if an error occures and data.error === 'parser_error',
        then data.errors is an array with more detailed errors like i.e.:
        data.errors = ['body_missing_id']
        */
    } else{
        /*
        if everything is okay, the data object should look like:
        data = {
            body: {
                id: 'theParsedId'
            }
        }
        */
    }
});
```

## Options
The options object with its default values:
```js
var options = {
    /**
    * an array of strings according to the specification of node-request-parser,
    * that are always parsed from a request
    */
    alwaysParse: [],
    
    /**
    * an array of strings, which js types to exclude from sanitizing generally
    */
    excludeSanitizeTypes: ['boolean', 'number'],
    
    /**
    * a sanitize function
    */
    sanitizeFunction: undefined,
    
    /**
     * has to be a function that requires request headers and callback(err, user) and then returns user
     * object(or every object you like extracted from the headers) like getUserFromRequest(headers, callback)
     */
    authFunction: undefined,
    
    /**
     * disables regex check on input keys
     */
    disableRegex: false
}
```

#### alwaysParse
Put all keys in that you want to have parsed every time you use the parser.
```js
var alwaysParse = ['B*id', 'H*language'];
```

#### excludeSanitizeTypes
Put in all js types you want to generally exclude from sanitizing.
The types `boolean` and `number` are excluded by default if
you don't specify different. This is because most sanitizers
are only able to sanitize strings and passed numbers or
booleans would be converted to strings.
```js
var excludeSanitizeTypes = ['boolean', 'number'];
```

#### sanitizeFunction
A possibility to automatically sanitize parsed properties.
```js
var sanitizeFunction = function(propertyToSanitize) {
    return sanitizer.sanitize(propertyToSanitize);
}
```

#### authFunction
A possibility to lookup authorization data with a
parser call. Does not work with `parseSync()`.
```js
var authFunction = function(headers, callback) {
    //example database call
    database.findUserWithCookie(headers.customCookie, function(err, user) {
        if(err) callback(err, null);
        callback(null, user);
    });
}
```

#### disableRegex
Set to true if you trust yourself and like to save
computation time through disabling regex check of each key.

## License
This code available under the MIT License.
See License.md for details.