<?php
// DIC configuration

/** @var Pimple\Container $container */

use League\Fractal\Manager;
use League\Fractal\Serializer\ArraySerializer;

$container = $astraApp->getContainer();

// Symfony Event Dispatcher
$container['dispatcher'] = function () {
    return new \Symfony\Component\EventDispatcher\EventDispatcher();;
};

// Error Handler
$container['errorHandler'] = function ($c) {
    return new \GetAstra\Exceptions\ErrorHandler($c['settings']['displayErrorDetails']);
};

// 404 handler so that there is no response if an invalid Astra API url is reached
/*$container['notFoundHandler'] = function ($c) {
    return '';
};*/

unset($container['errorHandler']);

// Responder
$container['responder'] = function ($c) {
    return new \GetAstra\Middleware\Responder($c);
};

// Create SQLite Database File if required
if($container['settings']['database']['driver'] == 'sqlite' && !file_exists($container['settings']['database']['database'])){
    touch($container['settings']['database']['database']);
}

// App Service Providers
$container->register(new \GetAstra\Services\Database\EloquentServiceProvider());

// Service Provider for Authentication
$container->register(new \GetAstra\Services\Auth\AuthServiceProvider());

// view renderer
$container['renderer'] = function ($c) {
    $settings = $c->get('settings')['renderer'];

    return new Slim\Views\PhpRenderer($settings['template_path']);
};

// monolog
$container['logger'] = function ($c) {
    $settings = $c->get('settings')['logger'];
    $logger = new Monolog\Logger($settings['name']);
    $logger->pushProcessor(new Monolog\Processor\UidProcessor());
    $logger->pushHandler(new Monolog\Handler\StreamHandler($settings['path'], $settings['level']));

    return $logger;
};

$schemaCheck = new \GetAstra\Middleware\DBSchema($container);

if(!$schemaCheck->exists()){
    $schemaCheck->createIfMissing();
}

// Options
$container['options'] = function ($c) {
    return new \GetAstra\Helpers\OptionsHelper($c);
};

//$container->get('options')->getOption('ak');

// Plugins
$container['plugins'] = function ($c) {
    return new \GetAstra\Managers\PluginManager($c);;
};

$container->get('plugins')->runAllPlugins();
$routesFiles = $container->get('plugins')->getRoutesFiles();

// Jwt Middleware
$container['jwt'] = function ($c) {

    $jws_settings = $c->get('settings')['jwt'];
    return new \Slim\Middleware\JwtAuthentication($jws_settings);
};


// APIs which work with/without authentication
$container['optionalAuth'] = function ($c) {
  return new \GetAstra\Middleware\OptionalAuth($c);
};

// APIs secured with APIAuth
$container['apiAuth'] = function ($c) {
    $api_settings = $c->get('settings')['apiAuth'];
    return new \GetAstra\Middleware\ApiAuth($c, $api_settings);
};

// Request Validator
$container['validator'] = function ($c) {
    \Respect\Validation\Validator::with('\\GetAstra\\Validation\\Rules');

    return new \GetAstra\Validation\Validator();
};

// Fractal
$container['fractal'] = function ($c) {
    $manager = new Manager();
    $manager->setSerializer(new ArraySerializer());

    return $manager;
};

$astraApp->add(new \GetAstra\Middleware\Responder($container));