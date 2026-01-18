<?php
/**
 * This file is part of the Astra Security Suite
 *
 *  Copyright (c) 2019 (https://www.getastra.com/)
 *
 *  For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
 *
 */

/**
 *
 *
 * @author HumansofAstra-WZ <help@getastra.com>
 * @date   2019-04-13
 */


namespace GetAstra\Controllers\Auth;

use Firebase\JWT\JWT;
use GetAstra\Helpers\OptionsHelper;
use GetAstra\Models\User;
use GetAstra\Transformers\UserTransformer;
use Interop\Container\ContainerInterface;
use League\Fractal\Resource\Item;
use Slim\Http\Request;
use Slim\Http\Response;
use Respect\Validation\Validator as v;

class InitController
{

    /** @var \GetAstra\Validation\Validator */
    protected $validator;
    /** @var \Illuminate\Database\Capsule\Manager */
    protected $db;
    /** @var \League\Fractal\Manager */
    protected $fractal;
    /** @var \GetAstra\Services\Auth\Auth */
    private $auth;

    /**
     * RegisterController constructor.
     *
     * @param \Interop\Container\ContainerInterface $container
     */
    public function __construct(ContainerInterface $container)
    {
        $this->auth = $container->get('auth');
        $this->validator = $container->get('validator');
        $this->db = $container->get('db');
        $this->fractal = $container->get('fractal');
    }

    /**
     * Return token after successful login
     *
     * @param \Slim\Http\Request $request
     * @param \Slim\Http\Response $response
     *
     * @return \Slim\Http\Response
     */
    public function init(Request $request, Response $response)
    {
        $validation = $this->validateInitRequest($tokenParams = $request->getParam('tokens'));

        if ($validation->failed()) {
            return $response->withJson(['errors' => ['tokens' => ['Received empty tokens']]], 422);
        }

        if ($this->validateIfKeysAlreadySet()) {
            return $response->withJson(['errors' => ['tokens' => ['Keys are already set']]], 422);
        }

        $tokenParams['token'] = (string)$tokenParams['token'];
        $tokenParams['refresh_token'] = (string)$tokenParams['refresh_token'];

        OptionsHelper::set('jwtToken', '', 'yes');
        OptionsHelper::set('jwtRefreshToken', '', 'yes');

        OptionsHelper::set('jwtToken', $tokenParams['token'], 'yes', 'core');
        OptionsHelper::set('jwtRefreshToken', $tokenParams['refresh_token'], 'yes', 'core');

        return $response->withJson(['success' => true]);
    }


    /**
     * @param array
     *
     * @return \GetAstra\Validation\Validator
     */
    protected function validateInitRequest($values)
    {
        return $this->validator->validateArray($values,
            [
                'token' => v::noWhitespace()->notEmpty(),
                'refresh_token' => v::noWhitespace()->notEmpty(),
            ]);
    }

    protected function validateIfKeysAlreadySet()
    {
        $token = (string)OptionsHelper::get('jwtToken', '');
        $refreshToken = (string)OptionsHelper::get('jwtRefreshToken', '');

        if (!empty($token) && !empty($refreshToken)) {
            return true;
        }

        return false;
    }
}