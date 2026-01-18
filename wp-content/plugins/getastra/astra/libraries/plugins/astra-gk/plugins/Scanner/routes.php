<?php
/**
 * Created by PhpStorm.
 * User: anandakrishna
 * Date: 2019-03-09
 * Time: 21:15
 */

use GetAstra\Plugins\Scanner\Controllers\Report\IssueController;
use GetAstra\Plugins\Scanner\Controllers\Scan\ScanController;
use GetAstra\Plugins\Scanner\Controllers\Scan\StatusController;
use GetAstra\Plugins\Scanner\Controllers\Scan\TestController;


$astraApp->group('/astra-api/plugins/scanner', function () {

    $optionalAuth = $this->getContainer()->get('optionalAuth');
    //$apiAuth = $this->getContainer()->get('apiAuth');

    $this->get('/scan', ScanController::class . ':index')->setName('plugins.scanner.scans.index');
    $this->post('/scan', ScanController::class . ':start')->setName('plugins.scanner.scans.start');
    $this->delete('/scan', ScanController::class . ':stop')->setName('plugins.scanner.scans.stop');

    /* Scan */
    //$this->post('/scan/do/testAjax', ScanController::class . ':testAjax')->setName('plugins.scanner.testAjax');
    //$this->get('/scan/do', ScanController::class . ':doScan')->setName('plugins.scanner.scans.perform');
    $this->get('/scan/health', ScanController::class . ':health')->setName('plugins.scanner.scans.health');

    /* Scan Status */
    $this->get('/status', StatusController::class . ':index')->setName('plugins.scanner.status.index');
    $this->delete('/status', StatusController::class . ':destroy')->setName('plugins.scanner.status.destroy');

    /* Issues */
    $this->get('/issues', IssueController::class . ':index')->setName('plugins.scanner.issues.index');
    $this->delete('/issues', IssueController::class . ':destroy')->setName('plugins.scanner.issues.destroy');
    $this->post('/deleteFile', IssueController::class . ':deleteFile')->setName('plugins.scanner.issue.deletefile');

    $this->get('/verifyMalwarePrefixes', TestController::class . ':verifyMalwarePrefixes')->setName('plugins.scanner.test.verifyMalwarePrefixes');


    //$this->put('/scans/{id}', ScanController::class . ':update')->setName('plugins.scanner.scans.update');


})->add($apiAuth);

$astraApp->group('/astra-api/plugins/scanner', function () {
    $this->post('/scan/do/testAjax', ScanController::class . ':testAjax')->setName('plugins.scanner.testAjax');
    $this->get('/scan/do', ScanController::class . ':doScan')->setName('plugins.scanner.scans.perform');
});