<?php

// Define root path
defined('ASTRAROOT') ?: define('ASTRAROOT', dirname(__DIR__) . DIRECTORY_SEPARATOR);

// Define doc root
$path = getcwd() . DIRECTORY_SEPARATOR;

$basePath = "";
$possibleBreakWords = array('/wp-content/', '/catalog/controller/extension/', '/sites/all/modules/', '/modules/', '/app/code/', '/astra/');

foreach ($possibleBreakWords as $word) {
    if (strpos($path, $word) !== false) {
        $basePath = strstr($path, $word, true) . DIRECTORY_SEPARATOR;
        break;
    }
}

if (empty($basePath)) {
    $basePath = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : getcwd();
}

defined('ASTRA_DOC_ROOT') ?: define('ASTRA_DOC_ROOT', $basePath);

// Load .env file

if (file_exists(ASTRAROOT . '.env.local')) {
    $dotenv = new Dotenv\Dotenv(ASTRAROOT, '.env.local');
    $dotenv->load();
} else if (file_exists(ASTRAROOT . '.env')) {
    $dotenv = new Dotenv\Dotenv(ASTRAROOT);
    $dotenv->load();
} else {

    putenv('DB_CONNECTION=sqlite');
    putenv('DB_HOST=127.0.0.1');
    putenv('DB_PORT=3306');
    putenv('DB_DATABASE=var/db/secure.sqlite');
    putenv('DB_USERNAME=root');
    putenv('DB_PASSWORD=root');
    putenv('DB_PREFIX=gk_');
    putenv('API_URL_HTTPS=https://api.getastra.com/');
    putenv('API_URL_HTTP=http://api.getastra.com/');

}

defined('ASTRA_DB_DRIVER') ?: define('ASTRA_DB_DRIVER', !empty(getenv('DB_CONNECTION')) ? getenv('DB_CONNECTION') : 'sqlite');

return [
    'settings' => [
        'displayErrorDetails' => getenv('APP_DEBUG') === 'true' ? true : false, // set to false in production
        'addContentLengthHeader' => false, // Allow the web server to send the content-length header

        // App Settings
        'app' => [
            'name' => getenv('APP_NAME') ?: 'Application secured by Astra Security Suite',
            'url' => getenv('APP_URL'),
            'env' => null !== getenv('APP_ENV') ? getenv('APP_ENV') : 'production',
        ],

        // Renderer settings
        'renderer' => [
            'template_path' => __DIR__ . '/../templates/',
        ],

        // Monolog settings
        'logger' => [
            'name' => getenv('APP_NAME'),
            'path' => isset($_ENV['docker']) ? 'php://stdout' : __DIR__ . '/../var/logs/app.log',
            'level' => \Monolog\Logger::DEBUG,
        ],

        // Database settings
        'database' => [
            'driver' => getenv('DB_CONNECTION'),
            'host' => getenv('DB_HOST'),
            'database' => getenv('DB_CONNECTION') == 'sqlite' ? ASTRAROOT . 'var' . DIRECTORY_SEPARATOR . 'db' . DIRECTORY_SEPARATOR . md5(__FILE__) . '.db' : getenv('DB_DATABASE'),
            'username' => getenv('DB_USERNAME'),
            'password' => getenv('DB_PASSWORD'),
            'port' => getenv('DB_PORT'),
            'charset' => 'utf8',
            'collation' => 'utf8_unicode_ci',
            'prefix' => getenv('DB_PREFIX'),
        ],

        'cors' => null !== getenv('CORS_ALLOWED_ORIGINS') ? getenv('CORS_ALLOWED_ORIGINS') : '*',

        // jwt settings
        'jwt' => [
            'secret' => null !== getenv('JWT_SECRET') ? getenv('JWT_SECRET') : "",
            'secure' => false,
            "environment" => "HTTP_X_TOKEN",
            "header" => "X-Token",
            "regexp" => "/(.*)/",
            'passthrough' => ['OPTIONS'],
            "error" => function ($request, $response, $arguments) {
                $data["status"] = "error";
                $data["message"] = $arguments["message"];
                return $response
                    ->withHeader("Content-Type", "application/json")
                    ->withHeader('X-Halt-Request', true)
                    ->write(json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
            }
            //'path' => '/astra-api',
        ],

        'apiAuth' => [
            'secure' => false,
            "environment" => "HTTP_X_TOKEN",
            "header" => "X-Token",
            'passthrough' => ['OPTIONS'],
        ],

        // plugins
        'plugins' => [
            'path' => !empty(getenv('PLUGINS_PATH')) ? getenv('PLUGINS_PATH') : __DIR__ . '/../plugins/',
        ],

        // relay/api
        'relay' => [
            'api_url_https' => !empty(getenv('API_URL_HTTPS')) ? getenv('API_URL_HTTPS') : 'https://api.getastra.com/api/',
            'api_url_http' => !empty(getenv('API_URL_HTTP')) ? getenv('API_URL_HTTP') : 'http://api.getastra.com/api/',
        ],
    ],
];
