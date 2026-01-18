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
 * @date   2019-03-20
 */

namespace GetAstra\Helpers;

use Curl\Curl;
use Firebase\JWT\JWT;
use GetAstra\Plugins\Scanner\Helpers\StatusHelper;
use Psr\Http\Message\ResponseInterface;

class RelayHelper
{

    /**
     * @var ClientInterface
     */
    protected $client;

    /**
     * Constructor
     *
     * @param ClientInterface $client
     */
    public function __construct()
    {
        $this->client = $this->getClient();
    }

    protected function getClient()
    {

        $baseUrl = $this->getApiUrl();

        try {
            $client = new Curl($baseUrl);
        } catch (\Exception $exception) {
            return null;
        }

        $jwt = $this->getJWT();
        $client->setHeader('Authorization', 'Bearer ' . $jwt);
        $client->setUserAgent('GetAstra.com UA ' . (defined('_ASTRA_VERSION_') ? _ASTRA_VERSION_ : '[Unknown version]'));
        $client->setConnectTimeout(9);
        $client->setDefaultJsonDecoder($assoc = true);
        $client->setOpt(CURLOPT_SSL_VERIFYHOST, false);
        $client->setOpt(CURLOPT_SSL_VERIFYPEER, false);

        return $client;
    }

    protected function getApiUrl()
    {
        $settings = require ASTRAROOT . 'app/settings.php';
        $relaySettings = $settings['settings']['relay'];

        if (!$this->supportsSSL()) {
            return $relaySettings['api_url_http'];
        }

        return $relaySettings['api_url_https'];
    }

    /**
     * Check if server supports SSL or not
     *
     * @return bool
     */
    protected function supportsSSL()
    {
        $version = curl_version();
        if ($version['features'] & CURL_VERSION_SSL) {
            return true;
        }

        return false;
    }

    protected function getJWT()
    {
        $jwt = (string)OptionsHelper::get('jwtToken', '', false);

        if (empty($jwt)) {
            StatusHelper::add(1, 'errors', 'Empty jwt received so return');
            return false;
        }

        $b = explode(".", $jwt);

        list($header, $payload, $signature) = explode(".", $jwt);

        $payload = json_decode(base64_decode($payload));
        $now = strtotime('-1 hour');

        if (!isset($payload->exp)) {
            return false;
        }

        if ($payload->exp > $now) {
            return $jwt;
        }

        return $this->getFreshJWT();
    }

    protected function getFreshJWT()
    {
        $refreshToken = (string)OptionsHelper::get('jwtRefreshToken');

        $baseUrl = $this->getApiUrl();

        try {
            $client = new Curl($baseUrl);
        } catch (\Exception $exception) {
            return false;
        }

        $client->setUserAgent('GetAstra.com UA ' . (defined('_ASTRA_VERSION_') ? _ASTRA_VERSION_ : '[Unknown version]'));
        $client->setConnectTimeout(9);
        $client->setDefaultJsonDecoder($assoc = true);
        $client->setOpt(CURLOPT_SSL_VERIFYHOST, false);
        $client->setOpt(CURLOPT_SSL_VERIFYPEER, false);

        $client->setHeader('Accept', 'application/json');
        $client->post('/api/token/refresh', array(
            'refresh_token' => $refreshToken
        ));

        $statusCode = $client->getHttpStatusCode();

        if ($statusCode !== 200) {
            StatusHelper::add(1, 'error', "{$statusCode} error during token refresh_token ({$refreshToken})");
            return false;
        }

        $newJwt = $client->response['token'];
        $newRefreshToken = $client->response['refresh_token'];

        OptionsHelper::set('jwtToken', $newJwt);
        OptionsHelper::set('jwtRefreshToken', $newRefreshToken);

        StatusHelper::add(1, 'relay', "Got new JWT " . strlen($newJwt) . " and Refresh Token");

        return $newJwt;

    }

    /**
     * Check the response status code.
     *
     * @param ResponseInterface $response
     * @param int $expectedStatusCode
     *
     * @throws \RuntimeException on unexpected status code
     */
    protected function checkResponseStatusCode($client, $expectedStatusCode, $default = '')
    {
        $statusCode = $client->getHttpStatusCode();

        if ($statusCode !== $expectedStatusCode) {
            return $default;
        }

        return $client->response;
    }

    protected function isConnected()
    {
        OptionsHelper::get('astraConnected');
    }
}