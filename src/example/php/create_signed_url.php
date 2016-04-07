<?php

// Provide timestamp, connection, and signature credentials
$timestamp = time() * 1000;
// The server id is encrypted in the signature and is verified on
// the server compared against the hmac-server-id which is set 
// in the config file /etc/guacamole/guacamole.properties
$hmacServerId = 10000001;
$connectionName = 'test-pc';
$hostName = '10.2.3.4';
$port = 3389;
$hmacMessage = $timestamp.'rdp'.$hmacServerId.'hostname'.$hostName.'port'.$port;
$hmacSecret = 'secret';
$signature = base64_encode(hash_hmac('sha1', $hmacMessage, $hmacSecret, true));
$url = 'http://guacamole.local:8080/guacamole/#/client/'.
	$connectionName.'?'.
	'timestamp='.$timestamp.
	'&connection='.$connectionName.
	'&signature='.urlencode($signature);
echo $url;
