<?php

$value = 'something from somewhere';

setcookie("TestCookie", $value);
setcookie("TestCookie", $value, time()+3600);
setcookie("TestCookie", $value, time()+3600, "/~jeff/", ".example.com", 1);

?>
<html>
    <head>
        <title>Sample Login</title>
    </head>
    <body>
        <h1>Hello, World!</h1>
    </body>
</html>
