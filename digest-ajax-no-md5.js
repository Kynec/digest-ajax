/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2014 Kynec Studios, Andrew Mitchell
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
(function($) {
    DigestAjax = function() {};
    
    ////////////////////////////////////////////////////////////////////////////
    //      AuthHelper Function
    ////////////////////////////////////////////////////////////////////////////
    /**
     * This function is intended to be overriden to help supply credentials.
     * <p>
     * Instead of hard-coding a username/password in settings and passing 
     * it on each AJAX request, this method is called whenever a request 
     * is challenged for credentials. This method should return an Object 
     * with the username/password which will then be used to 
     * authenticate.
     * <p>
     * By default this method will return an empty username/password combo, 
     * but it can be overriden to prompt the user for a username and/or 
     * password.
     * @returns {Object} Object that must contain a 'username' and 
     *          'password' key/value pair
     */
    DigestAjax.authHelper = function() {
        return {
            username: '',
            password: ''
        };
    };
    ////////////////////////////////////////////////////////////////////////////
    //      HA1/Username Store
    ////////////////////////////////////////////////////////////////////////////
    /**Temporary storage of a generated HA1 value*/
    DigestAjax.UNAUTH_HA1 = null;
    /**
     * If Digest authentication succeeds, the temporary HA1 is transferred to 
     * this value, where it is used for future requests.
     */
    DigestAjax.AUTH_HA1 = null;
    /**Temporary storage of provided username*/
    DigestAjax.UNAUTH_USERNAME = null;
    /**
     * If Digest authentication succeeds, username is stored in this value for 
     * future requests.
     */
    DigestAjax.AUTH_USERNAME = null;
    /**
     * Value of the WWW-Authenticate header name to retrieve. This can be 
     * changed if the server is returning authentication information on a 
     * different header name value. This is commonly the case when avoiding 
     * built-in browser authentication prompts.
     */
    DigestAjax.WWW_AUTHENTICATE = 'WWW-Authenticate';
    ////////////////////////////////////////////////////////////////////////////
    //      Primary AJAX Digest Authentication Function
    ////////////////////////////////////////////////////////////////////////////
    /**
     * Submits an AJAX request with optional credentials to handle 
     * Digest authentication.
     * @param {(String | Object)} url the URL of the request, or settings Object
     * @param {(Object | String)} settings settings Object, or username
     * @param {String} username username, or password if username was provided 
     *          instead of settings
     * @param {String} password password
     * @returns {Promise} promise interface to call back for AJAX results
     */
    DigestAjax.ajaxDigest = function(url, settings, username, password) {
        //Settings, username, and password variables
        var s = {}, u, p;
        
        //Extract the path from the URL, which is used for qop
        var a = document.createElement('a');
        if (typeof url === 'object') {
            //ajaxDigest(settings)
            s = url;
            a.href = s.url;
        }
        else if (typeof url === 'string') {
            if (typeof settings === 'string') {
                //ajaxDigest(url, username, password)
                u = settings ? settings : null;
                p = username ? username : null;
            }
            else if (typeof settings === 'object') {
                //ajaxDigest(url, settings, username, password)
                s = settings ? settings : {};
                u = username ? username : null;
                p = password ? password : null;
            }
            a.href = url;
            s.url = url;
        }
        
        s = $.extend({
            requestUri: a.pathname + a.search,
            username: u,
            password: p,
            type: 'GET'
        }, s);

        var dfd = $.Deferred();
        return dfd.promise(doAjaxUnauthorized());

        function doAjaxUnauthorized() {
            //If the request is successful, invoke callbacks immediately 
            //without using Digest authentication
            return $.ajax(s)
                .done(function(data, textStatus, jqXHR) {
                    dfd.resolve(data, textStatus, jqXHR);
                })
                .fail(function(jqXHR, textStatus, errorThrown) {
                    //Only attempt Digest authentication on a 401/407 response
                    if (jqXHR.status === 401 || jqXHR.status === 407) {
                        doAjaxAuthorized(createAuthorizationHeader(jqXHR));
                    }
                    else {
                        dfd.reject(jqXHR, textStatus, errorThrown);
                    }
                });
        }

        function doAjaxAuthorized(header) {
            if (s.headers === undefined) {
                s.headers = {};
            }
            s.headers.Authorization = header;
            return $.ajax(s)
                .done(function(data, textStatus, jqXHR) {
                    if (DigestAjax.UNAUTH_HA1 !== null) {
                        DigestAjax.AUTH_HA1 = DigestAjax.UNAUTH_HA1;
                        DigestAjax.UNAUTH_HA1 = null;
                    }
                    if (DigestAjax.UNAUTH_USERNAME !== null) {
                        DigestAjax.AUTH_USERNAME = DigestAjax.UNAUTH_USERNAME;
                        DigestAjax.UNAUTH_USERNAME = null;
                    }
                    dfd.resolve(data, textStatus, jqXHR);
                })
                .fail(function(jqXHR, textStatus, errorThrown) {
                    if (jqXHR.status === 401 || jqXHR.status === 407) {
                        DigestAjax.AUTH_HA1 = null;
                        DigestAjax.AUTH_USERNAME = null;
                    }
                    dfd.reject(jqXHR, textStatus, errorThrown);
                });
        }

        function createAuthorizationHeader(xhr) {
            var header = xhr.getResponseHeader(DigestAjax.WWW_AUTHENTICATE);
            if (header !== undefined && header !== null) {
                var params = parseWWWAuthenticateHeader(header);

                var qop = params.qop;
                var clientQop = 'auth';
                if (qop !== undefined && qop.toLowerCase() === 'auth-int') {
                    clientQop = 'auth-int';
                }

                //HA1 Calculation
                var algorithm = params.algorithm;
                var ha1;
                var username;
                var cnonce;
                if (DigestAjax.AUTH_HA1 !== null) {
                    ha1 = DigestAjax.AUTH_HA1;
                    username = DigestAjax.AUTH_USERNAME;
                }
                else {
                    if (s.username === null || s.password === null) {
                        var auth = $.extend({
                            username: '',
                            password: ''
                        }, DigestAjax.authHelper());
                        $.extend(s, auth);
                    }
                    if (algorithm !== undefined && algorithm.toLowerCase() === 'md5-sess') {
                        cnonce = generateCnonce();
                        ha1 = CryptoJS.MD5(CryptoJS.MD5(s.username + ':' 
                                + params.realm + ':' + s.password) + ':' 
                                + params.nonce + ':' + cnonce);
                    }
                    else {
                        ha1 = CryptoJS.MD5(s.username + ':' + params.realm + ':' + s.password);
                    }
                    username = s.username;
                    DigestAjax.UNAUTH_HA1 = ha1;
                    DigestAjax.UNAUTH_USERNAME = s.username;
                }

                //HA2 Calculation
                var ha2, response;
                if (clientQop === 'auth-int') {
                    var body = s.data ? s.data : '';
                    ha2 = CryptoJS.MD5(s.type + ':' + s.requestUri + ':' + CryptoJS.MD5(body));
                }
                else {
                    ha2 = CryptoJS.MD5(s.type + ':' + s.requestUri);
                }

                //Response Calculation
                var response, nc;
                if (params.qop === undefined) {
                    response = CryptoJS.MD5(ha1 + ':' + params.nonce + ':' + ha2);
                }
                else {
                    //Cnonce Calculation
                    if (cnonce === undefined) {
                        //Cnonce may have been generated already for MD5-sess algorithm
                        cnonce = generateCnonce();
                    }
                    nc = '00000001';
                    response = CryptoJS.MD5(ha1 + ':' + params.nonce + ':' 
                            + nc + ':' + cnonce + ':' + clientQop + ':' + ha2);
                }

                var sb = [];
                sb.push('Digest username="', username, '",');
                sb.push('realm="', params.realm, '",');
                sb.push('nonce="', params.nonce, '",');
                sb.push('uri="', s.requestUri, '",');
                sb.push('qop=', clientQop, ',');
                if (nc !== undefined) {
                    sb.push('nc=', nc, ',');
                }
                if (cnonce !== undefined) {
                    sb.push('cnonce="', cnonce, '",');
                }
                if (params.opaque !== undefined) {
                    sb.push('opaque="', params.opaque, '",');
                }
                sb.push('response="', response, '"');
                return sb.join('');
            }
        }
        function parseWWWAuthenticateHeader(header) {
            var params = {};
            var regex = /([^"',\s]*)="([^"]*)/gm;
            var result = null;
            do {
                result = regex.exec(header);
                if (result !== null) {
                    params[result[1]] = result[2];
                }
            }
            while (result !== null);
            return params;
        }
        function generateCnonce() {
            var cnonceChars = 'abcdef0123456789';
            var cnonce = '';
            for (var i = 0; i < 8; i++) {
                var randNum = Math.floor(Math.random() * cnonceChars.length);
                cnonce += cnonceChars.substr(randNum, 1);
            }
            return cnonce;
        }
    };
    DigestAjax.ajaxDigestType = function(type, url, settings, username, password) {
        if (typeof settings === 'string') {
            password = username;
            username = settings;
        }

        if (typeof settings !== 'object') {
            settings = {};
        }
        settings.type = type;
        return DigestAjax.ajaxDigest(url, settings, username, password);
    };
    DigestAjax.getDigest = function(url, settings, username, password) {
        return DigestAjax.ajaxDigestType('GET', url, settings, username, password);
    };
    DigestAjax.postDigest = function(url, settings, username, password) {
        return DigestAjax.ajaxDigestType('POST', url, settings, username, password);
    };
    DigestAjax.putDigest = function(url, settings, username, password) {
        return DigestAjax.ajaxDigestType('PUT', url, settings, username, password);
    };
    DigestAjax.deleteDigest = function(url, settings, username, password) {
        return DigestAjax.ajaxDigestType('DELETE', url, settings, username, password);
    };
    $.extend({
        authHelper: function(call) {
            DigestAjax.authHelper = call;
        },        
        ajaxDigest: DigestAjax.ajaxDigest,
        ajaxDigestType: DigestAjax.ajaxDigestType,
        getDigest: DigestAjax.getDigest,
        postDigest: DigestAjax.postDigest,
        putDigest: DigestAjax.putDigest,
        deleteDigest: DigestAjax.deleteDigest
    });
} (jQuery));