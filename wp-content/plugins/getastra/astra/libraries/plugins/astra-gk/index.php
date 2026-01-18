<?php


if (version_compare(PHP_VERSION, '5.5.0', '<')) {
    header('Content-Type: application/json');
    echo json_encode(array(
        'errors' => array('PHP version of your server is ' . PHP_VERSION . ' whereas PHP >= 5.5.0 is required'),
    ));
    exit;
}

// Set default timezone to server time if available and UTC in other cases
date_default_timezone_set(date_default_timezone_get());


//if(strpos($_SERVER['REQUEST_URI'], '/astra-api') !== false){
//    die('404');
//}

if (isset($_GET['route'])) {
    $_SERVER['X_ASTRA_ORIGINAL_REQUEST_URI'] = $_SERVER['REQUEST_URI'];
    $_SERVER['REQUEST_URI'] = rtrim($_SERVER['SCRIPT_NAME'], '/') . '/' . urldecode($_GET['route']);
}

/*error_reporting(E_ALL); ini_set('display_errors', 1);*/
define('_ASTRA_VERSION_', '2.0.1');

if (PHP_SAPI == 'cli-server') {
    // To help the built-in PHP dev server, check if the request was actually for
    // something which should probably be served as a static file
    $url = parse_url($_SERVER['REQUEST_URI']);
    $file = __DIR__ . $url['path'];
    if (is_file($file)) {
        return false;
    }
}

/*
$url = $_SERVER['REQUEST_URI'];
if (strpos($url, 'admin') !== false) {
    return false;
}
*/

require __DIR__ . '/vendor/autoload.php';

session_start();

// Instantiate the app
$settings = require __DIR__ . '/app/settings.php';

// check requirements and exit if necessary
$boot = require __DIR__ . '/app/boot.php';

if (!empty($boot)) {
    //return false;
}

// Create the astraApp
$astraApp = new \Slim\App($settings);

// Set up dependencies
require __DIR__ . '/app/dependencies.php';

// Register middleware
require __DIR__ . '/app/middleware.php';

// Register routes
require __DIR__ . '/app/routes.php';

// Run app
$astraApp->run(true);