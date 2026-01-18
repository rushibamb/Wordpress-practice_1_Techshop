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
 * @date   2019-03-13
 */

namespace GetAstra\Plugins\Scanner\Controllers\Scan;

use GetAstra\Helpers\DBHelper;
use GetAstra\Plugins\Scanner\Helpers\ServerHelper;
use GetAstra\Plugins\Scanner\Models\ScanStatus;
use GetAstra\Plugins\Scanner\Services\ScanEngine;
use GetAstra\Plugins\Scanner\Helpers\ConfigHelper;
use GetAstra\Plugins\Scanner\Helpers\StatusHelper;
use GetAstra\Plugins\Scanner\Services\ScanService;
use Interop\Container\ContainerInterface;
use Slim\Http\Request;
use Slim\Http\Response;
use Respect\Validation\Validator as v;

class ScanController
{
    private $container;

    /**
     * UserController constructor.
     *
     * @param \Interop\Container\ContainerInterface $container
     *
     * @internal param $auth
     */
    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        $this->db = $container->get('db');
        $this->validator = $container->get('validator');

    }

    public function index(Request $request, Response $response, array $args)
    {
        return $response->withJson([
            'success' => true,
            'isRunning' => ScanEngine::isRunning(),
        ])->withHeader('X-Halt-Request', true);
    }

    public function start(Request $request, Response $response, array $args)
    {
        ignore_user_abort(true);

        ScanStatus::query()->truncate();


        StatusHelper::add(1, 'info', sprintf('Malware scan start request at %s via Astra API', date('l jS \of F Y h:i:s A', time())));

        //Validation
        //$validScanCode = v::Uuid()->notEmpty()->validate($request->getParam('scanCode'));
        $validScanCode = v::notEmpty()->validate($request->getParam('scanCode'));
        $validSiteIri = v::notEmpty()->validate($request->getParam('siteIri'));

        if (!$validScanCode) {
            return $response->withJson([
                'success' => false,
                'status' => 'failed',
                'errorCode' => 'scanner.scan.scanCodeEmpty',
                'statusDesc' => 'Received an invalid scan code'
            ]);
        }

        if (!$validSiteIri) {
            return $response->withJson([
                'success' => false,
                'status' => 'failed',
                'errorCode' => 'scanner.scan.siteIriIncorrect',
                'statusDesc' => 'Received an invalid site IRI'
            ]);
        }

        if (isset($_GET['route'])) { // When pretty url fix
            $baseUri = (string)$request->getUri()->getBaseUrl();
            $queryPath = (string)$request->getUri()->getQuery();
            $uri = $baseUri . '?' . urldecode($queryPath);
        } else {
            $uri = (string)$request->getUri();
        }

        ConfigHelper::set('baseUrl', '', 'no');

        ServerHelper::saveBaseUrlIfNotTest($uri);

        // Make sure a scan is not running by getting a 'lock' so that we can proceed with the scan
        if (ScanEngine::isRunning()) {
            StatusHelper::add(1, 'info', sprintf('Scan is already running so exiting at %s', date('l jS \of F Y h:i:s A', time())));
            return $response->withJson([
                'success' => false,
                'status' => 'failed',
                'statusDesc' => 'Scan is already running',
                'errorCode' => 'scanner.scan.unableToGetLock',
            ]);
        }

        try {

            // Store the unique scan code issues by SF
            $scanCode = (string)$request->getParam('scanCode');
            $siteIri = (string)$request->getParam('siteIri');

            ConfigHelper::set('scanCode', '');
            ConfigHelper::set('siteIri', '');

            ConfigHelper::set('scanCode', $scanCode);
            ConfigHelper::set('siteIri', $siteIri);
            ConfigHelper::set('killRequested', 0);

            $startScan = ScanEngine::startScan();

        } catch (Exception $e) {
            ConfigHelper::set('lastScanCompleted', $e->getMessage());
            ConfigHelper::set('lastScanFailureType', "general");

            return $response->withJson([
                'success' => false,
                'status' => 'failed',
                'statusDesc' => $e->getCode(),
                'error' => $e->getMessage()
            ]);
        }

        return $response->withJson([
            'success' => true,
            'status' => 'started',
            'statusDesc' => 'Scan has started at ' . date('m/d/Y H:i:s', time()),
        ]);
    }

    public function stop(Request $request, Response $response, array $args)
    {
        StatusHelper::add(1, 'info', 'Scan stop request received from Astra');
        ConfigHelper::clearScanLock(); //Clear the lock now because there may not be a scan running to pick up the kill request and clear the lock

        ScanEngine::requestKill();
        ConfigHelper::delete('scanStartAttempt');
        ConfigHelper::set('lastScanFailureType', false);

        return $response->withJson(['success' => true]);

    }

    public function testAjax(Request $request, Response $response, array $args)
    {
        return $response->withHeader('Content-Type', 'text/plain')->write('SCANTESTOK');
    }

    public function doScan(Request $request, Response $response, array $args)
    {
        ignore_user_abort(true);

        ScanService::scanMain($request, $response, $args);

        //return $response->withHeader('Content-Type', 'text/plain')->write('SCANTESTOK');
    }

    public function health(Request $request, Response $response, array $args)
    {
        DBHelper::vacuumDB();

        return $response->withJson([
            'success' => true,
            'server' => $_SERVER,
        ])->withHeader('X-Halt-Request', true);
    }

}