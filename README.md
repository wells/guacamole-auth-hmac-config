# guacamole-auth-hmac-config [![Build Status](https://travis-ci.org/wells/guacamole-auth-hmac-config.png?branch=master)](https://travis-ci.org/wells/guacamole-auth-hmac-config)

## Description

This project is a plugin for [Guacamole](http://guac-dev.org), an HTML5 based
remote desktop solution supporting VNC/RFB, RDP, and SSH.

This plugin is an _authentication provider_ that enables stateless, on-the-fly
configuration of remote desktop connections that are authorized using a
pre-shared key. It is most appropriate for scenarios where you have an existing
user authentication & authorization mechanism.

## Building

`guacamole-auth-hmac-config` uses Maven for managing builds. 
After installing Maven you can build a  suitable jar for deployment 
with `mvn package`.

The resulting jar file will be placed in 
`target/guacamole-auth-hmac-config-<version>.jar`.

## Deployment & Configuration

**Warning** This plugin runs on Guacamole 0.9.9, so you must be running
at least that version before using this plugin.

Copy `guacamole-auth-hmac-config-<version>.jar` to the location specified by
[`lib-directory`][config-classpath] in `guacamole.properties`. You no 
longer need to set then `auth-provider` property, as the latest versions 
of guacamole auto load all included authentication provider extensions.

`guacamole-auth-hmac-config` adds three new config keys to `guacamole.properties`:

 * `hmac-server-id` - The key that is embedded in the signature by the server 
    generating the connection URL.
 * `secret-key` - The key that will be used to verify URL signatures.
    Whatever is generating the signed URLs will need to share this value.
 * `timestamp-age-limit` - A numeric value (in milliseconds) that determines how long
    a signed request should be valid for.

In addition you should include an `hmac-config.xml` file in the same directory as
`guacamole.properties`. This provides the system with a set named connections to select
from during the authentication process.

An [example hmac-config.xml][example-config] is included in `src/test/resources`.

[example-config]: https://github.com/wells/guacamole-auth-hmac-config/blob/master/src/test/resources

[config-classpath]: http://guac-dev.org/doc/gug/configuring-guacamole.html

## Usage

To generate a signed URL for usage with this plugin, simply use the path to
Guacamole's built-in `#/client/...?` as a base, and append the following query
parameters:

 * `timestamp` - A unix timestamp in milliseconds (i.e. `time() * 1000` in PHP).
   This is used to prevent replay attacks.
 * `connection` - The name of one of the provided connection configs in `hmac-config.xml`.
 * `signature` - The [request signature][#request-signing]

## Request Signing

Requests must be signed with an HMAC, where the message content is 
generated from the request parameters as follows:

 1. The parameters `timestamp`, `protocol`, and `hmacServerId` are concatenated.
 2. For `hostname` and `port` append their name followed by value.

### Request Signing - Example

Given a request for the following URL:

`#/client/test-pc?timestamp=1377143741000&connection=test-pc&signature=Z5eootsOIdYruq1rYnN2%2B%2Fo92fE%3D`

The message to be signed will be the concatenation of the following 
strings:

  - timestamp: `"1377143741000"`
  - protocol: `"rdp"`
  - hmacServerId: `"10000001"`
  - hostname: `"hostname10.2.3.4"`
  - port: `"port3389"`

Assuming a secret key of `"secret"`, a `signature` parameter should be appended
with a value that is the base-64 encoded value of the hash produced by signing
the message `"1377143741000rdp10000001hostname10.2.3.4port3389"` with the key
`"secret"`, or `"Z5eootsOIdYruq1rYnN2+/o92fE="`. How
this signature is produced is dependent on your programming language/platform,
but with recent versions of PHP it looks like this:

    base64_encode(hash_hmac('sha1', $message, $secret));

Also, don't forget to `urlencode()` the `signature` parameter in the URL.

An [example PHP implementation][example-php] is included in `src/example/php`.

[example-php]: https://github.com/wells/guacamole-auth-hmac-config/blob/master/src/example/php

## Vagrant Test Environment

1. Build this extension with `mvn package`
2. Install vagrant: https://vagrantup.com
3. Visit the sourceforge binary folder for Guacamole:
https://sourceforge.net/projects/guacamole/files/current/binary
4. Locate guacamole-<version>.war and download it to `src/target`
5. Visit the sourceforge source folder for Guacamole:
https://sourceforge.net/projects/guacamole/files/current/source/
6. Locate guacamole-server-<version>.tar.gz and download it to `src/target`
7. Navigate to the location of this repository on your computer
(i.e. where the Vagrantfile is located) with your terminal
8. Enter the command `vagrant up` on your terminal to launch and 
provision a test server. This will take some time to download **and** setup.

**Please note:**

You will want to modify the `guacamole.properties` and `hmac-config.xml` 
files on the test server to match your necessary configuration. They are
located at `/etc/guacamole/`. 

Please reference `install.sh` for more details, and don't forget to 
`service tomcat7 restart` after modifying these files. 

If you need to enter debug logging mode, you can do so by editing the file located
at `/usr/share/tomcat7/webapps/guacamole/WEB-INF/classes/logback.xml` and restart
the tomcat service again.

## License

Apache License 2.0
