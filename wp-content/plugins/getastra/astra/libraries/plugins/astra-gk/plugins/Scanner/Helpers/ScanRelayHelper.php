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
 * @date   2019-03-23
 */

namespace GetAstra\Plugins\Scanner\Helpers;


use GetAstra\Helpers\OptionsHelper;
use GetAstra\Helpers\RelayHelper;
use GetAstra\Plugins\Scanner\Helpers\ConfigHelper;
use GetAstra\Plugins\Scanner\Helpers\StatusHelper;

class ScanRelayHelper extends RelayHelper
{

    public function getChecksums($cms, $version, $locale = '')
    {
        $client = $this->getClient();

        $client->setHeader('Accept', 'application/json');
        $response = $client->get('/api/plugins/scanner/checksums', array(
            'cms' => $cms,
            'version' => $version,
            'locale' => $locale,
            'itemsPerPage' => 1
        ));

        $response = $this->checkResponseStatusCode($client, 200, array('a' => 'b'));

        return $response;
    }


    public function getSignatures()
    {
        $client = $this->getClient();

        $client->setHeader('Accept', 'application/json');
        $response = $client->get('/api/plugins/scanner/signatures');

        $response = $this->checkResponseStatusCode($client, 200);

        return $response;
    }

    public function addIssue($data)
    {
        $data['site'] = ConfigHelper::get('siteIri');;
        $data['scan'] = ConfigHelper::get('scanCode');
        $data['data'] = json_decode($data['data']);

        $client = $this->getClient();

        $client->setHeader('Accept', 'application/json');
        $client->setHeader('Content-Type', 'application/json');
        $response = $client->post('/api/plugins/scanner/issues', $data);

        $log = $client->response;

        //StatusHelper::add('4', 'relay', 'Received response code: ' . json_encode($log));
        $response = $this->checkResponseStatusCode($client, 201);

        return $response;
    }

    public function updateScanStatus($data)
    {

    }

    public function sendMetrics()
    {
        $client = $this->getClient();

        $client->setHeader('Accept', 'application/json');
        $client->setHeader('Content-Type', 'application/json');
        $client->setHeader('X-HTTP-METHOD-OVERRIDE', 'PUT');

        $data = [
            'status' => 'completed',
            'duration' => ConfigHelper::get('scanDuration', 2),
            'fileCount' => ConfigHelper::get('totalFilesScanned', 0),
            'metrics' => [
                'totalFiles' => ConfigHelper::get('totalFiles', 0),
                'remainingFiles' => ConfigHelper::get('remainingFiles', 0),
                'scanningRate' => ConfigHelper::get('fileRate', 0),
            ]
        ];

        $scanUrl = ConfigHelper::get('scanCode', '0', false);

        \GetAstra\Plugins\Scanner\Helpers\StatusHelper::add('4', 'relay', $scanUrl);
        $response = $client->post($scanUrl, $data);

    }

    public function sendScanStatus($status = 'running', $message = 'Scan is running')
    {
        $client = $this->getClient();

        $client->setHeader('Accept', 'application/json');
        $client->setHeader('Content-Type', 'application/json');
        $client->setHeader('X-HTTP-METHOD-OVERRIDE', 'PUT');

        $startTime = (int)ConfigHelper::get('startTime');
        $scanDuration = (time() - $startTime) / 60;


        $data = [
            'status' => $status,
            'statusDesc' => $message,
            'duration' => $scanDuration,
            'fileCount' => ConfigHelper::get('totalFilesScanned', 0),
            'metrics' => [
                'totalFiles' => ConfigHelper::get('totalFiles', 0),
                'remainingFiles' => ConfigHelper::get('remainingFiles', 0),
                'scanningRate' => ConfigHelper::get('fileRate', 0),
            ]
        ];

        $scanUrl = ConfigHelper::get('scanCode', '0', false);

        $response = $client->post($scanUrl, $data);

        $log = $client->response;
        StatusHelper::add('4', 'relay', 'sendScanStatus: ' . json_encode($log));

    }

    public function sendCmsDetails($cms, $version, $locale = 'none')
    {
        $client = $this->getClient();

        $client->setHeader('Accept', 'application/json');
        $client->setHeader('Content-Type', 'application/json');
        $client->setHeader('X-HTTP-METHOD-OVERRIDE', 'PUT');

        $data = array(
            'cms' => array(
                'cms' => $cms,
                'version' => $version,
                'locale' => $locale,
            ),
        );

        $scanUrl = ConfigHelper::get('scanCode', '0', false);

        $response = $client->post($scanUrl, $data);

        $log = $client->response;
        StatusHelper::add('4', 'relay', 'sendCmsDetails: ' . json_encode($log));
    }

    /**
     * This function triggers a bounce request -> it gets the astra server to trigger a scan fork if self-requests are
     * blocked on a client.
     * @param $cronKey
     * @param $isFork
     * @param $scanUrl
     */
    public function sendBounceRequest($cronKey, $isFork, $scanUrl) {
        $client = $this->getClient();
        $client->setHeader('Accept', 'application/json');
        $client->setHeader('Content-Type', 'application/json');
        $client->setTimeout(3);
        $isFork = $isFork ? '1' : '0';
        $scanUrl .= '/bounce';
        $data = [
            'cronKey' => $cronKey,
            'isFork' => $isFork,
        ];
        $client->post($scanUrl,$data);
        $log = $client->response;
        StatusHelper::add('4', 'relay', 'sendBounceRequest: ' . json_encode($log));
    }
}