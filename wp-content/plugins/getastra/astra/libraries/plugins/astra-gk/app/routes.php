<?php

use GetAstra\Controllers\Auth\InitController;
use GetAstra\Controllers\Auth\RegisterController;
use GetAstra\Controllers\Option\OptionController;

use Slim\Http\Request;
use Slim\Http\Response;


// Api Routes

$apiAuth = $container['apiAuth'];

$astraApp->group('/astra-api',
    function () {
        $jwtMiddleware = $this->getContainer()->get('jwt');

        //$optionalAuth = $this->getContainer()->get('optionalAuth');
        /** @var \Slim\App $this */


        $this->get('/options', OptionController::class . ':index')->setName('option.index');
        $this->post('/options', OptionController::class . ':store')->setName('option.store');
        $this->get('/options/{name}', OptionController::class . ':show')->setName('option.show');
        $this->put('/options/{name}', OptionController::class . ':update')->setName('option.update');
        $this->delete('/options/{name}', OptionController::class . ':destroy')->setName('option.destroy');


        // Auth Routes
        $this->post('/users', RegisterController::class . ':register')->setName('auth.register');
        $this->post('/users/login', LoginController::class . ':login')->setName('auth.login');

        $this->post('/auth/init', InitController::class . ':init')->setName('auth.init');
        /*
        // User Routes
        $this->get('/user', UserController::class . ':show')->add($jwtMiddleware)->setName('user.show');
        $this->put('/user', UserController::class . ':update')->add($optionalAuth)->setName('user.update');
        */

    })->add($apiAuth);


// Routes created by Plugins

foreach ($routesFiles as $routesFile) {
    include_once($routesFile);
}

$astraApp->get('/astra-api',
    function (Request $request, Response $response, array $args) {
        return $response->withJson([
            'ping' => 'pong'
        ]);
    });
