var expect = require('chai').expect,
    RequestParser = require('../node-request-parser'),
    httpMocks = require('node-mocks-http'),
    sanitizer = require('sanitizer'),
    completeMock,
    missingMock,
    userMap = {'8439235fe34abc37c832fadd21': 'max', '8439235fe34abc37c832faddff': 'monika'};

describe('request-parser tests', function() {
    before(function() {
        completeMock = httpMocks.createRequest({
            method: 'POST',
            url: '/test/post',
            body: {
                id: 42,
                user: { name: 'Max Mustermann', age: 21},
                bool: true
            },
            params: {
                id: -2,
                malicious: 'This is<html> a <script>You are doomed!</script>sanitize </html>test!'
            },
            query: {
                bool: false,
                malicious: 'This string is <html><script>You are doomed!</script>not </html>malicious!'
            },
            headers: {
                cookie: '8439235fe34abc37c832fadd21',
                lang: 'de'
            }
        });

        missingMock = httpMocks.createRequest({
            method: 'POST',
            url: '/test/post',
            body: {
                id: 42,
            },
            params: {
            },
            query: {
                bool: false,
            },
            headers: {
                lang: 'de'
            }
        });
    });

    describe('simple tests', function() {
        it('dummy test -> should simply pass', function() {
            expect(undefined).to.equal(undefined);
        });

        it('create object test -> should create new object instance', function() {
            var parser;
            expect(typeof(parser)).not.to.equal('object');
            parser = new RequestParser();
            expect(typeof(parser)).to.equal('object');
        });
    });

    describe('positive tests', function() {
        it('parse -> should return correct data', function() {
            var parser = new RequestParser({ authFunction: function(headers, callback){
                if(!headers.cookie) return callback('no cookie header found', null);
                if(!userMap[headers.cookie]) return callback('no username to cookie found', null);
                callback(null, userMap[headers.cookie]);
            }});
            parser.parse(completeMock, ['Hcookie', 'Pid', 'Pmalicious', 'Qbool', 'Qmalicious', 'A', 'Bid', 'Buser', 'Bbool'], function(err, data){
                if(err){
                    if(data) console.error(data);
                    expect(err.toString()).to.equal(undefined);
                } else{
                    expect(data.headers.cookie).to.equal(completeMock.headers.cookie);
                    expect(data.headers.lang).to.equal(undefined);
                    expect(data.params.id).to.equal(completeMock.params.id);
                    expect(data.params.malicious).to.equal(completeMock.params.malicious);
                    expect(data.query.bool).to.equal(completeMock.query.bool);
                    expect(data.query.malicious).to.equal(completeMock.query.malicious);
                    expect(data.body.id).to.equal(completeMock.body.id);
                    expect(data.body.user).to.equal(completeMock.body.user);
                    expect(data.body.bool).to.equal(completeMock.body.bool);
                    expect(data.authorization).to.equal('max');
                }
            });
        });

        it('parse -> should correctly sanitize', function() {
            var parser = new RequestParser({ sanitizeFunction: sanitizer.sanitize });
            parser.parse(completeMock, ['H*cookie', 'P*id', 'P*malicious', 'Q*bool', 'Q*malicious', 'B*id', 'B*bool'], function(err, data){
                if(err){
                    if(data) console.error(data);
                    expect(err.toString()).to.equal(undefined);
                } else{
                    expect(data.headers.cookie).to.equal(completeMock.headers.cookie);
                    expect(data.headers.lang).to.equal(undefined);
                    expect(data.params.id).to.equal(completeMock.params.id);
                    expect(data.params.malicious).to.equal('This is a sanitize test!');
                    expect(data.query.bool).to.equal(completeMock.query.bool);
                    expect(data.query.malicious).to.equal('This string is not malicious!');
                    expect(data.body.id).to.equal(completeMock.body.id);
                    expect(data.body.bool).to.equal(completeMock.body.bool);
                }
            });
        });

        it('parse -> should correctly use optional parameters', function () {
            var parser = new RequestParser({sanitizeFunction: sanitizer.sanitize});
            parser.parse(missingMock, ['H*cookie?', 'Buser?'], function (err, data) {
                if(err){
                    if(data) console.error(data);
                    expect(err.toString()).to.equal(undefined);
                } else{
                    expect(data.headers.cookie).to.equal(undefined);
                    expect(data.body.user).to.equal(undefined);
                }
            });
        });

        it('parse -> should correctly use alwaysParse array', function () {
            var parser = new RequestParser({sanitizeFunction: sanitizer.sanitize, alwaysParse: ['Hlang']});
            parser.parse(missingMock, ['H*cookie?', 'Buser?'], function (err, data) {
                if(err){
                    if(data) console.error(data);
                    expect(err.toString()).to.equal(undefined);
                } else{
                    expect(data.headers.cookie).to.equal(undefined);
                    expect(data.body.user).to.equal(undefined);
                    expect(data.headers.lang).to.equal(missingMock.headers.lang);
                }
            });
        });
    });

    describe('negative tests', function() {
        it('parse -> should fail with missing json params', function () {
            var parser = new RequestParser({sanitizeFunction: sanitizer.sanitize});
            parser.parse(missingMock, ['H*cookie', 'Buser'], function (err, data) {
                expect(err.toString()).to.equal('parser_error');
                expect(data.length).to.equal(2);
            });
        });

        it('parse -> should fail with missing auth', function () {
            var parser = new RequestParser({ authFunction: function(headers, callback){
                if(!headers.cookie) return callback('no cookie header found', null);
                if(!userMap[headers.cookie]) return callback('no username to cookie found', null);
                callback(null, userMap[headers.cookie]);
            }});
            parser.parse(missingMock, ['A'], function (err, data) {
                expect(err.toString()).to.equal('no cookie header found');
                expect(data).to.equal(null);
            });
        });

        it('parse -> should fail with missing authFunction', function () {
            var parser = new RequestParser();
            parser.parse(missingMock, ['A'], function (err, data) {
                expect(err.toString()).to.equal('authFunction_not_set');
                expect(data).to.equal(null);
            });
        });

        it('parse -> should fail with missing sanitizeFunction', function () {
            var parser = new RequestParser();
            parser.parse(missingMock, ['B*id'], function (err, data) {
                expect(err.toString()).to.equal('sanitizeFunction_not_set');
                expect(data).to.equal(null);
            });
        });

    });
});