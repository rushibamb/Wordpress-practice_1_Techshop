<?php

namespace GetAstra\Middleware;

use GetAstra\Helpers\OptionsHelper;
use Interop\Container\ContainerInterface;
use Slim\DeferredCallable;

class ApiAuth
{

    /**
     * @var \Interop\Container\ContainerInterface
     */
    private $container;

    private $message;

    private $settings;

    /**
     * OptionalAuth constructor.
     *
     * @param \Interop\Container\ContainerInterface $container
     *
     * @internal param \Slim\Middleware\JwtAuthentication $jwt
     */
    public function __construct(ContainerInterface $container, $settings)
    {
        $this->container = $container;
        $this->settings = $settings;
    }

    /**
     * ApiAuth middleware invokable class to verify API token when present in Request
     *
     * @param  \Psr\Http\Message\ServerRequestInterface $request PSR7 request
     * @param  \Psr\Http\Message\ResponseInterface $response PSR7 response
     * @param  callable $next Next middleware
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function __invoke($request, $response, $next)
    {
        $path = (string)$request->getUri()->getPath();
        $isApi = strpos($path, 'astra-api') !== false;

        if (!$isApi) {
            return $next($request, $response);
        }

        /* If token cannot be found return with 401 Unauthorized. */
        $token = $this->fetchToken($request);

        if (false === $token) {
            return $response->withJson([
                'success' => false,
                'status' => 'failed',
                'errorCode' => '',
                'message' => $this->message
            ], 401);
        }

        if (false === $this->validToken($token)) {
            return $response->withJson([
                'success' => false,
                'status' => 'failed',
                'errorCode' => '',
                'message' => $this->message
            ], 401);
        }

        return $next($request, $response);
    }

    /**
     * Fetch the access token
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @return string|null Base64 encoded JSON Web Token or null if not found.
     */
    public function fetchToken($request)
    {

        /* If using PHP in CGI mode and non standard environment */
        $server_params = $request->getServerParams();
        $header = "";
        $message = "";


        $settings_env = $this->settings['environment'];

        if (isset($server_params[$settings_env])) {
            $message = "Using token from environment";
            $header = $server_params[$settings_env];
        }

        /* Nothing in environment, try header instead */
        if (empty($header)) {
            $message = "Using token from request header";
            $headers = $request->getHeader($this->settings["header"]);
            $header = isset($headers[0]) ? $headers[0] : "";
        }

        /* Try apache_request_headers() as last resort */
        if (empty($header) && function_exists("apache_request_headers")) {
            $message = "Using token from apache_request_headers()";
            $headers = apache_request_headers();
            $header = isset($headers[$this->settings["header"]]) ? $headers[$this->settings["header"]] : "";
        }

        if (!empty($header)) {
            return $header;
        }
        /* If everything fails log and return false. */
        $this->message = "Token not found";
        return false;
    }

    public function validToken($token)
    {
        $storedToken = (string)OptionsHelper::get('apiAuthToken', '');

        if ($storedToken === $token) {
            return true;
        }

        if (empty($storedToken)) {
            $token = (string)$token;
            OptionsHelper::set('apiAuthToken', '', 'yes');
            OptionsHelper::set('apiAuthToken', $token, 'yes');
            return true;
        }

        /* If everything fails log and return false. */
        $this->message = "Received token is invalid: " . $token;
        return false;
    }

}
