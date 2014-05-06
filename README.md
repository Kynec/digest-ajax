digest-ajax
===========

Digest Authentication for JavaScript jQuery AJAX Requests

**digest-ajax** extends the functionality of jQuery's AJAX request by resubmitting a failed authentication request (401 and 407) with user-provided credentials.

####Requirements

Requires jQuery (though a future version may make this requirement optional). Also depends on CryptoJS for MD5 digest. The main version is bundled with the CryptoJS MD5 rollup, though a non-bundled version is available.

##Syntax

**digest-ajax** uses nearly identical syntax to jQuery's AJAX method. Below is an example to request a resource with Digest authentication:

```
$.ajaxDigest('http://example.com/resource', {
    username: 'user',
    password: 'pass'
}).done(function(data, textStatus, jqXHR) {
    alert('Retrieved data!');
}).fail(function(jqXHR, textStatus, errorThrown) {
    alert('Request failed :(');
});
```

**digest-ajax's** ajaxDigest method returns the jQuery Deferred object's Promise interface, upon which done, fail, and always can be called just like normal AJAX syntax. These functions will only fire upon a successful or failed authentication. 

**digest-ajax** will submit an unauthenticated request first, and then attempt a second request with authentication if an appropriate WWW-Authenticate header is found, calling the returned Promise interface only once.

All request functions can be made with the following parameters:

- $.ajaxDigest(settings)
- $.ajaxDigest(url, settings)
- $.ajaxDigest(url, settings, username, password)

Where 'settings' is the normal jQuery AJAX Object settings parameter, 'url' is the normal jQuery AJAX String url parameter, and username and password are String credentials to use for authentication. The username and password can also be set in the 'settings' object as 'username' and 'password' properties respectively.

##Auth Helper

Rather than hard-coding a username and password (though perfectly viable), **digest-ajax** provides a callback method to retrieve a user's username and password dynamically. This can be achieved by returning an Object with the 'username' and 'password' property set:

```
$.authHelper(function() {
    //Ex: get username/password from elements
    var username = $('#username').val(); 
    var password = $('#password').val();
    return {
        username: username,
        password: password
    };
});


//Or without jQuery
DigestAjax.authHelper = function() {
    /* Return username/password logic */
}
```

##Credentials Cache

Upon making a successful request, **digest-ajax** will store the username and generated Digest HA1 value that made the succcessful request. Subsequent requests will attempt to use the stores username and HA1 to authenticate if prompted. Should the credentials fail, it will forget the stored credentials.

##Methods

Other than the ajaxDigest method, there are multiple method shorthands for different AJAX requests. The methods are stored on the global DigestAjax object, and can be accessed via the object or through jQuery. The following is a list of methods available with **digest-ajax**:

- **DigestAjax.ajaxDigest()** and **$.ajaxDigest()** (Defaults to GET)
- **DigestAjax.getDigest()** and **$.getDigest()**
- **DigestAjax.postDigest() and **$.postDigest()**
- **DigestAjax.putDigest()**** and **$.putDigest()**
- **DigestAjax.deleteDigest()** and **$.deleteDigest()**
- **DigestAjax.authHelper** (Assign to a function for credential callback)
- **$.authHelper(callback)** (Pass a function parameter for credential callback)

##License

**digest-ajax** is released under the MIT License. If you are incorporating it in a large work though, or if you have general comments about it, I would love to hear about it!
