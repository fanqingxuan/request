<?php

namespace Json;

use Json\Request\File;
use \Exception;
use UnexpectedValueException;

/**
 * Encapsulates request information for easy and secure access from application
 * controllers.
 *
 * The request object is a simple value object that is passed between the
 * dispatcher and controller classes. It packages the HTTP request environment.
 *
 *```php
 * use Json\Request;
 *
 * $request = new Request();
 *
 * if ($request->isPost() && $request->isAjax()) {
 *     echo "Request was made using POST and AJAX";
 * }
 *
 * // Retrieve SERVER variables
 * $request->getServer("HTTP_HOST");
 *
 * // GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, PURGE, TRACE, CONNECT
 * $request->getMethod();
 *
 * // An array of languages the client accepts
 * $request->getLanguages();
 *```
 */
class Request
{

    /**
     * @var bool
     */
    private $httpMethodParameterOverride = false;
    
    public function sethttpMethodParameterOverride($value) {
        $this->httpMethodParameterOverride = $value;
    }
    
    public function gethttpMethodParameterOverride() {
        return $this->httpMethodParameterOverride;
    }

    /**
     * @var array
     */

    private $putCache;

    private $rawBody;

    /**
     * @var bool
     */
    private $strictHostCheck = false;

    /**
     * Gets a variable from the $_REQUEST superglobal applying filters if
     * needed. If no parameters are given the $_REQUEST superglobal is returned
     *
     *```php
     * // Returns value from $_REQUEST["user_email"] without sanitizing
     * $userEmail = $request->get("user_email");
     *
     * // Returns value from $_REQUEST["user_email"] with sanitizing
     * $userEmail = $request->get("user_email", "email");
     *```
     */
    public function get($name = null, $defaultValue = null)
    {
        return $this->getHelper(
            $_REQUEST,
            $name,
            $defaultValue
        );
    }

    /**
     * Gets an array with mime/types and their quality accepted by the
     * browser/client from _SERVER["HTTP_ACCEPT"]
     */
    public function getAcceptableContent()
    {
        return $this->getQualityHeader("HTTP_ACCEPT", "accept");
    }

    /**
     * Gets auth info accepted by the browser/client from
     * $_SERVER["PHP_AUTH_USER"]
     */
    public function getBasicAuth()
    {
        if (!$this->hasServer("PHP_AUTH_USER") || !$this->hasServer("PHP_AUTH_PW")) {
            return null;
        }

        return [
            "username"=> $this->getServer("PHP_AUTH_USER"),
            "password"=> $this->getServer("PHP_AUTH_PW")
        ];
    }

    /**
     * Gets best mime/type accepted by the browser/client from
     * _SERVER["HTTP_ACCEPT"]
     */
    public function getBestAccept()
    {
        return $this->getBestQuality($this->getAcceptableContent(), "accept");
    }

    /**
     * Gets best charset accepted by the browser/client from
     * _SERVER["HTTP_ACCEPT_CHARSET"]
     */
    public function getBestCharset()
    {
        return $this->getBestQuality($this->getClientCharsets(), "charset");
    }

    /**
     * Gets best language accepted by the browser/client from
     * _SERVER["HTTP_ACCEPT_LANGUAGE"]
     */
    public function getBestLanguage()
    {
        return $this->getBestQuality($this->getLanguages(), "language");
    }

    /**
     * Gets most possible client IPv4 Address. This method searches in
     * `$_SERVER["REMOTE_ADDR"]` and optionally in
     * `$_SERVER["HTTP_X_FORWARDED_FOR"]`
     */
    public function getClientAddress($trustForwardedHeader = false)
    {
        $server = $this->getServerArray();
        $address = null;
        /**
         * Proxies uses this IP
         */
        if ($trustForwardedHeader) {
            $address = $server["HTTP_X_FORWARDED_FOR"];

            if ($address === null) {
                $address = $server["HTTP_CLIENT_IP"];
            }
        }

        if ($address === null) {
            $address = $server["REMOTE_ADDR"];
        }

        if (gettype($address) != "string") {
            return false;
        }

        return explode(",", $address)[0];

        return $address;
    }

    /**
     * Gets a charsets array and their quality accepted by the browser/client
     * from _SERVER["HTTP_ACCEPT_CHARSET"]
     */
    public function getClientCharsets()
    {
        return $this->getQualityHeader("HTTP_ACCEPT_CHARSET", "charset");
    }

    /**
     * Gets content type which request has been made
     */
    public function getContentType()
    {
        $server = $this->getServerArray();

        return $server["CONTENT_TYPE"];
    }

    /**
     * Gets auth info accepted by the browser/client from
     * $_SERVER["PHP_AUTH_DIGEST"]
     */
    public function getDigestAuth()
    {
        $auth   = [];
        $server = $this->getServerArray();

        if (isset($server["PHP_AUTH_DIGEST"])) {
            $digest = $server["PHP_AUTH_DIGEST"];
            $matches = [];

            if (!preg_match_all("#(\\w+)=(['\"]?)([^'\" ,]+)\\2#", $digest, $matches, 2)) {
                return $auth;
            }

            if (gettype($matches) == "array") {
                foreach($matches as $match) {
                    $auth[$match[1]] = $match[3];
                }
            }
        }

        return $auth;
    }


    /**
     * Gets HTTP header from request data
     */
    final public function getHeader($header)
    {
        $name = strtoupper(
            strtr($header, "-", "_")
        );

        $server = $this->getServerArray();

        if (isset($server[$name]))  {
            return $server[name];
        }

        if (isset($server["HTTP_" . $name]))  {
            return $server["HTTP_" . $name];
        }

        return "";
    }

    /**
     * Returns the available headers in the request
     *
     * <code>
     * $_SERVER = [
     *     "PHP_AUTH_USER" => "json",
     *     "PHP_AUTH_PW"   => "secret",
     * ];
     *
     * $headers = $request->getHeaders();
     *
     * echo $headers["Authorization"]; // Basic cGhhbGNvbjpzZWNyZXQ=
     * </code>
     */
    public function getHeaders()
    {
        $headers = [];

        $contentHeaders = [
            "CONTENT_TYPE"=>  true,
            "CONTENT_LENGTH"=> true,
            "CONTENT_MD5"=>    true
        ];

        $server = $this->getServerArray();

        foreach($server as $name => $value) {
            // Note: The starts_with uses case insensitive search here
            if (strpos($name, "HTTP_") === 0) {
                $name = ucwords(
                    strtolower(
                        str_replace(
                            "_",
                            " ",
                            substr($name, 5)
                        )
                    )
                );

                $name = str_replace(" ", "-", $name);

                $headers[$name] = $value;

                continue;
            }

            // The "CONTENT_" headers are not prefixed with "HTTP_".
            $name = strtoupper($name);

            if (isset($contentHeaders[$name])) {
                $name = ucwords(
                    strtolower(
                        str_replace("_", " ", $name)
                    )
                );

                $name = str_replace(" ", "-", $name);

                $headers[$name] = $value;
            }
        }

        $authHeaders = $this->resolveAuthorizationHeaders();

        // Protect for future (child classes) changes
        $headers = array_merge($headers, $authHeaders);

        return $headers;
    }

    /**
     * Gets host name used by the request.
     *
     * `Request::getHttpHost` trying to find host name in following order:
     *
     * - `$_SERVER["HTTP_HOST"]`
     * - `$_SERVER["SERVER_NAME"]`
     * - `$_SERVER["SERVER_ADDR"]`
     *
     * Optionally `Request::getHttpHost` validates and clean host name.
     * The `Request::$strictHostCheck` can be used to validate host name.
     *
     * Note: validation and cleaning have a negative performance impact because
     * they use regular expressions.
     *
     * ```php
     * use Json\Request;
     *
     * $request = new Request;
     *
     * $_SERVER["HTTP_HOST"] = "example.com";
     * $request->getHttpHost(); // example.com
     *
     * $_SERVER["HTTP_HOST"] = "example.com:8080";
     * $request->getHttpHost(); // example.com:8080
     *
     * $request->setStrictHostCheck(true);
     * $_SERVER["HTTP_HOST"] = "ex=am~ple.com";
     * $request->getHttpHost(); // UnexpectedValueException
     *
     * $_SERVER["HTTP_HOST"] = "ExAmPlE.com";
     * $request->getHttpHost(); // example.com
     * ```
     */
    public function getHttpHost()
    {
        $strict = $this->strictHostCheck;

        /**
         * Get the server name from $_SERVER["HTTP_HOST"]
         */
        $host = $this->getServer("HTTP_HOST");

        if (!$host) {
            /**
             * Get the server name from $_SERVER["SERVER_NAME"]
             */
            $host = $this->getServer("SERVER_NAME");
            if (!$host) {
                /**
                 * Get the server address from $_SERVER["SERVER_ADDR"]
                 */
                $host = $this->getServer("SERVER_ADDR");
            }
        }

        if ($host && $strict) {
            /**
             * Cleanup. Force lowercase as per RFC 952/2181
             */
            $host = strtolower(
                trim($host)
            );

            if (memstr($host, ":")) {
                $host = preg_replace("/:[[:digit:]]+$/", "", $host);
            }

            /**
             * Host may contain only the ASCII letters 'a' through 'z'
             * (in a case-insensitive manner), the digits '0' through '9', and
             * the hyphen ('-') as per RFC 952/2181
             */
            if ("" !== preg_replace("/[a-z0-9-]+\.?/", "", $host)) {
                throw new UnexpectedValueException("Invalid host " . $host);
            }
        }

        return (string) $host;
    }

    /**
     * Gets web page that refers active request. ie: http://www.google.com
     */
    public function getHTTPReferer() 
    {
        $server = $this->getServerArray();

        if (!isset($server["HTTP_REFERER"])) {
            return "";
        }

        return $server["HTTP_REFERER"];
    }

    /**
     * Gets decoded JSON HTTP raw request body
     */
    public function getJsonRawBody($associative = false)
    {
        $rawBody = $this->getRawBody();

        if (gettype($rawBody) != "string") {
            return false;
        }

        return json_decode($rawBody, $associative);
    }

    /**
     * Gets languages array and their quality accepted by the browser/client
     * from _SERVER["HTTP_ACCEPT_LANGUAGE"]
     */
    public function getLanguages()
    {
        return $this->getQualityHeader("HTTP_ACCEPT_LANGUAGE", "language");
    }

    /**
     * Gets HTTP method which request has been made
     *
     * If the X-HTTP-Method-Override header is set, and if the method is a POST,
     * then it is used to determine the "real" intended HTTP method.
     *
     * The _method request parameter can also be used to determine the HTTP
     * method, but only if setHttpMethodParameterOverride(true) has been called.
     *
     * The method is always an uppercased string.
     */
    final public function getMethod()
    {
        $returnMethod = "";

        $server = $this->getServerArray();

        if (isset($server["REQUEST_METHOD"])) {
            $requestMethod = $server["REQUEST_METHOD"];
            $returnMethod = strtoupper($requestMethod);
        } else {
            return "GET";
        }

        if ("POST" === $returnMethod) {
            $overridedMethod = $this->getHeader("X-HTTP-METHOD-OVERRIDE");

            if (!empty($overridedMethod)) {
                $returnMethod = strtoupper($overridedMethod);
            } elseif ($this->httpMethodParameterOverride) {
                if (isset($_REQUEST["_method"])) {
                    $returnMethod = strtoupper($_REQUEST["_method"]);
                }
            }
        }

        if (!$this->isValidHttpMethod($returnMethod)) {
            return "GET";
        }

        return $returnMethod;
    }

    /**
     * Gets information about the port on which the request is made.
     */
    public function getPort()
    {

        /**
         * Get the server name from $_SERVER["HTTP_HOST"]
         */
        $host = $this->getServer("HTTP_HOST");

        if (!$host) {
            return (int) $this->getServer("SERVER_PORT");
        }

        $pos = strrpos($host, ":");

        if (false !== $pos) {
            return (int) substr($host, $pos + 1);
        }

        return "https" === $this->getScheme() ? 443 : 80;
    }

    /**
     * Gets a variable from the $_POST superglobal applying filters if needed
     * If no parameters are given the $_POST superglobal is returned
     *
     *```php
     * // Returns value from $_POST["user_email"] without sanitizing
     * $userEmail = $request->getPost("user_email");
     *
     * // Returns value from $_POST["user_email"] with sanitizing
     * $userEmail = $request->getPost("user_email", "email");
     *```
     */
    public function getPost($name = null, $defaultValue = null)
    {
        return $this->getHelper(
            $_POST,
            $name,
            $defaultValue
        );
    }

    /**
     * Gets a variable from put request
     *
     *```php
     * // Returns value from $_PUT["user_email"] without sanitizing
     * $userEmail = $request->getPut("user_email");
     *
     * // Returns value from $_PUT["user_email"] with sanitizing
     * $userEmail = $request->getPut("user_email", "email");
     *```
     */
    public function getPut($name = null, $defaultValue = null)
    {
        $put = $this->putCache;

        if (gettype($put) != "array") {
            $contentType = $this->getContentType();

            if (gettype($contentType) == "string" && stripos($contentType, "json") != false) {
                $put = $this->getJsonRawBody(true);

                if (gettype($put) != "array") {
                    $put = [];
                }
            } else {
                $put = [];

                parse_str($this->getRawBody(), $put);
            }

            $this->putCache = $put;
        }

        return $this->getHelper(
            $put,
            $name,
            $defaultValue
        );
    }

    /**
     * Gets variable from $_GET superglobal applying filters if needed
     * If no parameters are given the $_GET superglobal is returned
     *
     *```php
     * // Returns value from $_GET["id"] without sanitizing
     * $id = $request->getQuery("id");
     *
     * // Returns value from $_GET["id"] with sanitizing
     * $id = $request->getQuery("id", "int");
     *
     * // Returns value from $_GET["id"] with a default value
     * $id = $request->getQuery("id", null, 150);
     *```
     */
    public function getQuery($name = null, $defaultValue = null)
    {
        return $this->getHelper(
            $_GET,
            $name,
            $defaultValue
        );
    }

    /**
     * Gets HTTP raw request body
     */
    public function getRawBody()
    {
        $rawBody = $this->rawBody;

        if (empty($rawBody)) {
            $contents = file_get_contents("php://input");

            /**
             * We need store the read raw body because it can't be read again
             */
            $this->rawBody = $contents;

            return $contents;
        }

        return $rawBody;
    }

    /**
     * Gets HTTP schema (http/https)
     */
    public function getScheme()
    {
        $https = $this->getServer("HTTPS");

        if ($https && $https != "off") {
            return "https";
        }

        return "http";
    }

    /**
     * Gets variable from $_SERVER superglobal
     */
    public function getServer($name)
    {
        $server = $this->getServerArray();

        return @$server[$name];
    }

    /**
     * Gets active server address IP
     */
    public function getServerAddress()
    {
        $serverAddr = $this->getServer("SERVER_ADDR");

        if (null === $serverAddr) {
            return gethostbyname("localhost");
        }

        return $serverAddr;
    }

    /**
     * Gets active server name
     */
    public function getServerName()
    {
        $serverName = $this->getServer("SERVER_NAME");

        if (null === $serverName) {
            return "localhost";
        }

        return $serverName;
    }

    /**
     * Gets attached files as Json\Request\File instances
     */
    public function getUploadedFiles($onlySuccessful = false, $namedKeys = false)
    {
        $files = [];

        $superFiles = $_FILES;

        if (count($superFiles) > 0) {
            foreach($superFiles as $prefix => $input) {
                if (gettype($input["name"]) == "array") {
                    $smoothInput = $this->smoothFiles(
                        $input["name"],
                        $input["type"],
                        $input["tmp_name"],
                        $input["size"],
                        $input["error"],
                        $prefix
                    );

                    foreach($smoothInput as $file) {
                        if ($onlySuccessful == false || $file["error"] == UPLOAD_ERR_OK) {
                            $dataFile = [
                                "name"=>  $file["name"],
                                "type"=>    $file["type"],
                                "tmp_name"=> $file["tmp_name"],
                                "size"=>     $file["size"],
                                "error"=>    $file["error"]
                            ];

                            if ($namedKeys == true) {
                                $files[$file["key"]] = new File(
                                    $dataFile,
                                    $file["key"]
                                );
                            } else {
                                $files[] = new File(
                                    $dataFile,
                                    $file["key"]
                                );
                            }
                        }
                    }
                } else {
                    if ($onlySuccessful == false || $input["error"] == UPLOAD_ERR_OK) {
                        if ($namedKeys == true) {
                            $files[$prefix] = new File($input, $prefix);
                        } else {
                            $files[] = new File($input, $prefix);
                        }
                    }
                }
            }
        }

        return $files;
    }

    /**
     * Gets HTTP URI which request has been made to
     *
     *```php
     * // Returns /some/path?with=queryParams
     * $uri = $request->getURI();
     *
     * // Returns /some/path
     * $uri = $request->getURI(true);
     *```
     *
     * @param bool onlyPath If true, query part will be omitted
     * @return string
     */
    final public function getURI($onlyPath = false)
    {
        $requestURI = $this->getServer("REQUEST_URI");
        if (null === $requestURI) {
            return "";
        }

        if ($onlyPath) {
            $requestURI = explode('?', $requestURI)[0];
        }

        return $requestURI;
    }

    /**
     * Gets HTTP user agent used to made the request
     */
    public function getUserAgent()
    {
        $userAgent = $this->getServer("HTTP_USER_AGENT");
        if (null === $userAgent) {
            return "";
        }

        return $userAgent;
    }

    /**
     * Checks whether $_REQUEST superglobal has certain index
     */
    public function has($name)
    {
        return isset($_REQUEST[$name]);
    }

    /**
     * Returns if the request has files or not
     */
    public function hasFiles()
    {
        return $this->numFiles(true) > 0;
    }

    /**
     * Checks whether headers has certain index
     */
    final public function hasHeader($header)
    {
        $name = strtoupper(strtr(header, "-", "_"));

        return $this->hasServer($name) || $this->hasServer("HTTP_" . $name);
    }

    /**
     * Checks whether $_POST superglobal has certain index
     */
    public function hasPost($name)
    {
        return isset($_POST[$name]);
    }

    /**
     * Checks whether the PUT data has certain index
     */
    public function hasPut($name)
    {
        $put = $this->getPut();

        return isset($put[$name]);
    }

    /**
     * Checks whether $_GET superglobal has certain index
     */
    public function hasQuery($name)
    {
        return isset($_GET[$name]);
    }

    /**
     * Checks whether $_SERVER superglobal has certain index
     */
    final public function hasServer($name)
    {
        $server = $this->getServerArray();

        return isset($server[$name]);
    }

    /**
     * Checks whether request has been made using ajax
     */
    public function isAjax()
    {
        return $this->hasServer("HTTP_X_REQUESTED_WITH") && $this->getServer("HTTP_X_REQUESTED_WITH") === "XMLHttpRequest";
    }

    /**
     * Checks whether HTTP method is CONNECT.
     * if _SERVER["REQUEST_METHOD"]==="CONNECT"
     */
    public function isConnect()
    {
        return $this->getMethod() === "CONNECT";
    }

    /**
     * Checks whether HTTP method is DELETE.
     * if _SERVER["REQUEST_METHOD"]==="DELETE"
     */
    public function isDelete()
    {
        return $this->getMethod() === "DELETE";
    }

    /**
     * Checks whether HTTP method is GET.
     * if _SERVER["REQUEST_METHOD"]==="GET"
     */
    public function isGet()
    {
        return $this->getMethod() === "GET";
    }

    /**
     * Checks whether HTTP method is HEAD.
     * if _SERVER["REQUEST_METHOD"]==="HEAD"
     */
    public function isHead()
    {
        return $this->getMethod() === "HEAD";
    }

    /**
     * Check if HTTP method match any of the passed methods
     * When strict is true it checks if validated methods are real HTTP methods
     */
    public function isMethod($methods, $strict = false)
    {
        $httpMethod = $this->getMethod();

        if (gettype($methods) == "string") {
            if ($strict && !$this->isValidHttpMethod($methods)) {
                throw new Exception("Invalid HTTP method: " . $methods);
            }

            return $methods == $httpMethod;
        }

        if (gettype($methods) == "array") {
            foreach($methods as $method) {
                if ($this->isMethod($method, $strict)) {
                    return true;
                }
            }

            return false;
        }

        if ($strict) {
            throw new Exception("Invalid HTTP method: non-string");
        }

        return false;
    }

    /**
     * Checks whether HTTP method is OPTIONS.
     * if _SERVER["REQUEST_METHOD"]==="OPTIONS"
     */
    public function isOptions()
    {
        return $this->getMethod() === "OPTIONS";
    }

    /**
     * Checks whether HTTP method is PATCH.
     * if _SERVER["REQUEST_METHOD"]==="PATCH"
     */
    public function isPatch()
    {
        return $this->getMethod() === "PATCH";
    }

    /**
     * Checks whether HTTP method is POST.
     * if _SERVER["REQUEST_METHOD"]==="POST"
     */
    public function isPost()
    {
        return $this->getMethod() === "POST";
    }

    /**
     * Checks whether HTTP method is PUT.
     * if _SERVER["REQUEST_METHOD"]==="PUT"
     */
    public function isPut()
    {
        return $this->getMethod() === "PUT";
    }

    /**
     * Checks whether HTTP method is PURGE (Squid and Varnish support).
     * if _SERVER["REQUEST_METHOD"]==="PURGE"
     */
    public function isPurge()
    {
        return $this->getMethod() === "PURGE";
    }

    /**
     * Checks whether request has been made using any secure layer
     */
    public function isSecure()
    {
        return $this->getScheme() === "https";
    }

    /**
     * Checks if the `Request::getHttpHost` method will be use strict validation
     * of host name or not
     */
    public function isStrictHostCheck()
    {
        return $this->strictHostCheck;
    }

    /**
     * Checks whether request has been made using SOAP
     */
    public function isSoap()
    {

        if ($this->hasServer("HTTP_SOAPACTION")) {
            return true;
        }

        $contentType = $this->getContentType();

        if (empty($contentType)) {
            return false;
        }

        return memstr($contentType, "application/soap+xml");
    }

    /**
     * Checks whether HTTP method is TRACE.
     * if _SERVER["REQUEST_METHOD"]==="TRACE"
     */
    public function isTrace()
    {
        return $this->getMethod() === "TRACE";
    }

    /**
     * Checks if a method is a valid HTTP method
     */
    public function isValidHttpMethod($method)
    {
        switch (strtoupper($method)) {
            case "GET":
            case "POST":
            case "PUT":
            case "DELETE":
            case "HEAD":
            case "OPTIONS":
            case "PATCH":
            case "PURGE": // Squid and Varnish support
            case "TRACE":
            case "CONNECT":
                return true;
        }

        return false;
    }

    /**
     * Returns the number of files available
     */
    public function numFiles($onlySuccessful = false)
    {
        $files = $_FILES;
        $numberFiles = 0;
        if (gettype($files != "array")) {
            return 0;
        }

        foreach($files as $file) {
            if (isset($file["error"]))  {
                $error = $file["error"];
                if (gettype($error) != "array") {
                    if (!$error || !$onlySuccessful) {
                        $numberFiles++;
                    }
                }

                if (gettype($error) == "array") {
                    $numberFiles += $this->hasFileHelper(
                        $error,
                        $onlySuccessful
                    );
                }
            }
        }

        return $numberFiles;
    }


    /**
     * Sets if the `Request::getHttpHost` method must be use strict validation
     * of host name or not
     */
    public function setStrictHostCheck($flag = true)
    {
        $this->strictHostCheck = $flag;

        return $this;
    }

    /**
     * Process a request header and return the one with best quality
     */
    final protected function getBestQuality($qualityParts, $name)
    {
        $i = 0;
        $quality = 0.0;
        $selectedName = "";

        foreach($qualityParts as $accept) {
            if ($i == 0) {
                $quality = (double) $accept["quality"];
                $selectedName = $accept[$name];
            } else {
                $acceptQuality = (double) $accept["quality"];

                if ($acceptQuality > $quality) {
                    $quality = $acceptQuality;
                    $selectedName = $accept[$name];
                }
            }

            $i++;
        }

        return $selectedName;
    }

    /**
     * Helper to get data from superglobals, applying filters if needed.
     * If no parameters are given the superglobal is returned.
     */
    final protected function getHelper($source, $name = null, $defaultValue = null)
    {
        $value = null;

        if ($name === null) {
            return $source;
        }

        if (!isset($source[$name])){
            return $defaultValue;
        }
        $value = $source[$name];


        return $value;
    }

    /**
     * Recursively counts file in an array of files
     */
    final protected function hasFileHelper($data, $onlySuccessful)
    {
        $numberFiles = 0;

        if (gettype($data) != "array") {
            return 1;
        }

        foreach($data as $value) {
            if (gettype($value) != "array") {
                if (!$value || !$onlySuccessful) {
                    $numberFiles++;
                }
            }

            if (gettype($value == "array")) {
                $numberFiles += $this->hasFileHelper($value, $onlySuccessful);
            }
        }

        return $numberFiles;
    }

    /**
     * Process a request header and return an array of values with their qualities
     */
    final protected function getQualityHeader($serverIndex, $name)
    {
        $returnedParts = [];

        $parts = preg_split(
            "/,\\s*/",
            $this->getServer($serverIndex),
            -1,
            PREG_SPLIT_NO_EMPTY
        );

        foreach ($parts as $part) {
            $headerParts = [];

            foreach(preg_split("/\s*;\s*/", trim($part), -1, PREG_SPLIT_NO_EMPTY) as $headerPart) {
                if (strpos($headerPart, "=") !== false) {
                    $split = explode("=", $headerPart, 2);

                    if ($split[0] === "q") {
                        $headerParts["quality"] = (double) $split[1];
                    } else {
                        $headerParts[$split[0]] = $split[1];
                    }
                } else {
                    $headerParts[$name] = $headerPart;
                    $headerParts["quality"] = 1.0;
                }
            }

            $returnedParts[] = $headerParts;
        }

        return $returnedParts;
    }

    /**
     * Resolve authorization headers.
     */
    protected function resolveAuthorizationHeaders()
    {
        $headers = [];
        $authHeader = null;
        $server    = $this->getServerArray();


        if ($this->hasServer("PHP_AUTH_USER") && $this->hasServer("PHP_AUTH_PW")) {
            $headers["Php-Auth-User"] = $this->getServer("PHP_AUTH_USER");
            $headers["Php-Auth-Pw"]   = $this->getServer("PHP_AUTH_PW");
        } else {
            if ($this->hasServer("HTTP_AUTHORIZATION")) {
                $authHeader = $this->getServer("HTTP_AUTHORIZATION");
            } elseif ($this->hasServer("REDIRECT_HTTP_AUTHORIZATION")) {
                $authHeader = $this->getServer("REDIRECT_HTTP_AUTHORIZATION");
            }

            if ($authHeader) {
                if (stripos($authHeader, "basic ") === 0) {
                    $exploded = explode(
                        ":",
                        base64_decode(
                            substr($authHeader, 6)
                        ),
                        2
                    );

                    if (count($exploded) == 2) {
                        $headers["Php-Auth-User"] = exploded[0];
                        $headers["Php-Auth-Pw"]   = exploded[1];
                    }
                } elseif (stripos($authHeader, "digest ") === 0 && !$this->hasServer("PHP_AUTH_DIGEST")) {
                    $headers["Php-Auth-Digest"] = $authHeader;
                } elseif (stripos($authHeader, "bearer ") === 0) {
                    $headers["Authorization"] = $authHeader;
                }
            }
        }

        if (!isset($headers["Authorization"])) {
            if (isset($headers["Php-Auth-User"])) {
                $headers["Authorization"] = "Basic " . base64_encode($headers["Php-Auth-User"] . ":" . $headers["Php-Auth-Pw"]);
            } elseif (isset($headers["Php-Auth-Digest"]))  {
                $headers["Authorization"] = $headers["Php-Auth-Digest"];
            }
        }

        return $headers;
    }

    /**
     * Smooth out $_FILES to have plain array with all files uploaded
     */
    final protected function smoothFiles($names, $types, $tmp_names, $sizes, $errors, $prefix)
    {
        $files = [];

        foreach($names as $idx => $name) {
            $p = $prefix . "." . $idx;

            if (gettype($name) == "string") {
                $files[] = [
                    "name"=>     $name,
                    "type"=>     $types[$idx],
                    "tmp_name"=> $tmp_names[$idx],
                    "size"=>     $sizes[$idx],
                    "error"=>    $errors[$idx],
                    "key"=>      $p
                ];
            }

            if (gettype($name) == "array") {
                $parentFiles = $this->smoothFiles(
                    $names[$idx],
                    $types[$idx],
                    $tmp_names[$idx],
                    $sizes[$idx],
                    $errors[$idx],
                    $p
                );

                foreach($parentFiles as $file) {
                    $files[] = $file;
                }
            }
        }

        return $files;
    }


    private function getServerArray()
    {
        if ($_SERVER) {
            return $_SERVER;
        } else {
            return [];
        }
    }
}
