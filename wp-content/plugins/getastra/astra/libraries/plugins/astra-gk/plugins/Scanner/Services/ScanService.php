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
 * @date   2019-03-15
 */

namespace GetAstra\Plugins\Scanner\Services;

use GetAstra\Helpers\Cms\AbstractCmsHelper;
use GetAstra\Helpers\DBHelper;
use GetAstra\Plugins\Scanner\Helpers\ConfigHelper;
use GetAstra\Plugins\Scanner\Helpers\ScanRelayHelper;
use GetAstra\Plugins\Scanner\Helpers\ServerHelper;
use GetAstra\Plugins\Scanner\Helpers\StatusHelper;
use GetAstra\Plugins\Scanner\Models\IndexedFile;
use GetAstra\Plugins\Scanner\Models\Issue;
use GetAstra\Plugins\Scanner\Models\KnownFile;
use GetAstra\Plugins\Scanner\Models\ScanStatus;
use GetAstra\Plugins\Scanner\Models\Signature;
use GetAstra\Plugins\Scanner\Services\FileScanner;
use GetAstra\Plugins\Scanner\Models\Scan;
use Phinx\Db\Table\Index;
use Slim\Http\Request;
use Slim\Http\Response;

class ScanService
{

    public static $peakMemAtStart = 0;

    public static function scanMain(Request $request, Response $response, array $args)
    {
        self::$peakMemAtStart = memory_get_peak_usage(true);

        //TODO Check database connection
        //TODO Check if SchemaExists

        $receivedCronKey = $request->getParam('cronKey');

        if (strpos($receivedCronKey, '/do/testAjax') !== false) {
            $receivedCronKey = str_replace('/do/testAjax', '', $receivedCronKey);
        }

        self::checkCronKey($receivedCronKey);

        //roller = new FileScanner();

        ConfigHelper::delete('scanStartAttempt');

        $isFork = ($request->getParam('isFork') == '1' ? true : false);


        if (!$isFork) {
            StatusHelper::add(4, 'info', "Checking if scan is already running");
            if (!ConfigHelper::getScanLock()) {
                self::errorExit("There is already a scan running.");
            }

            ConfigHelper::updateScanStillRunning();
            ConfigHelper::set('peakMemory', 0, "no");
            ConfigHelper::set('lowResourceScanWaitStep', false);
        }

        //StatusHelper::add(4, 'info', "Requesting max memory");
        ServerHelper::requestMaxMemory();
        StatusHelper::add(4, 'info', "Setting up error handling environment");
        set_error_handler('GetAstra\Plugins\Scanner\Services\ScanService::error_handler', E_ALL ^ E_DEPRECATED);
        register_shutdown_function('GetAstra\Plugins\Scanner\Services\ScanService::shutdown');

        /* Start the scan */
        StatusHelper::add(4, 'info', "Setting up scanRunning and starting scan");

        @error_reporting(E_ALL);
        ServerHelper::iniSet('display_errors', 'On');

        // Update running status to Astra
        $relay = new ScanRelayHelper();
        $relay->sendScanStatus('running');

        try {
            if ($isFork) {
                // This is a forkedCall
                $scan = new ScanEngine();

                StatusHelper::add(4, 'info', "Loading the data since it is forked");

            } else {
                // FirstTime Call


                self::prepareScan();


                StatusHelper::add(1, 'info', "Contacting Astra to initiate scan");

                $malwarePrefixesHash = '';
                $coreHashesHash = '';
                
                ConfigHelper::set('startTime', time());
                ConfigHelper::set('filesIndexed', "", 'no');
                ConfigHelper::set('indexSize', 0, 'no');
                ConfigHelper::set('startRequireRemoteStart', false);

                ConfigHelper::set('filesToScan', "");
                ConfigHelper::set('jobList', "", 'no');
                ConfigHelper::set('lastScanCompleted', '', 'no');
                ConfigHelper::set('lastScanFailureType', '', 'no');

                $scan = new ScanEngine();
                //$scan->deleteNewIssues();
            }

            $scan->go();

        } catch (\Exception $e) {
            ConfigHelper::clearScanLock();
            $peakMemory = self::logPeakMemory();
            StatusHelper::add(2, 'info', "Scanner used " . ServerHelper::formatBytes($peakMemory - self::$peakMemAtStart) . " of memory for scan. Server peak memory usage was: " . ServerHelper::formatBytes($peakMemory));
            StatusHelper::add(2, 'error', "Scan terminated with error: " . $e->getMessage());
            exit();
        }

        ConfigHelper::clearScanLock();
        /**/


    }

    public static function prepareScan()
    {

        //DBHelper::vacuumDB();
        KnownFile::query()->truncate();
        IndexedFile::query()->truncate();
        Issue::query()->truncate();

        $relay = new ScanRelayHelper();

        // Import KnownFiles checksums
        $cmsAdapter = new AbstractCmsHelper();
        $cms = $cmsAdapter->getCms();

        $cmsName = $cms->getName();
        $cmsVersion = $cms->getVersion();

        ConfigHelper::set('cms', '', 'yes');

        $cmsLocale = '';
        if ('wordpress' === $cmsName && is_callable(array($cms, 'getLocale'))) {
            $cmsLocale = $cms->getLocale();
        }

        if (!empty($cmsName) && false !== $cmsName && false !== $cmsVersion) { // Only fetch knownFile hashes if we were able to detect the CMS

            ConfigHelper::set('cms', $cmsName, 'yes');
            if (!empty($cmsLocale)) {
                $checksums = $relay->getChecksums($cmsName, $cmsVersion, $cmsLocale);
                $relay->sendCmsDetails($cmsName, $cmsVersion, $cmsLocale);
            } else {
                $checksums = $relay->getChecksums($cmsName, $cmsVersion);
                $relay->sendCmsDetails($cmsName, $cmsVersion);
            }
            StatusHelper::add(1, 'info', "CMS version: $cmsName - version: $cmsVersion - locale: $cmsLocale ");
            if (isset($checksums['hashes'])) {
                $knownFiles = array();
                foreach ($checksums['hashes'] as $fileName => $hash) {
                    $knownFiles[] = array(
                        'path' => $fileName,
                        'md5' => $hash,
                    );
                }

                $chunks = array_chunk($knownFiles, 499); // Checksums need to be in chunks of 500 to be inserted into SQLite
                foreach ($chunks as $chunk) {
                    KnownFile::query()->insert($chunk); // Batch insert each chunk
                }

                StatusHelper::add(1, 'info', "Loaded " . count($knownFiles) . " known files");
            } else {
                StatusHelper::add(2, 'info', "Unable to get the checksums - " . json_encode($checksums));
            }
        }

        // Import Signatures
        $signatures = $relay->getSignatures();

        if (isset($signatures[0]['pattern'])) {

            Signature::query()->truncate();

            $importedSignatures = array();
            foreach ($signatures as $signature) {
                $importedSignatures[] = array(
                    'sig_id' => $signature['id'],
                    'pattern' => $signature['pattern'],
                    'name' => $signature['name'],
                    'description' => $signature['description'],
                    'scanType' => $signature['scanType'],
                    'logOnly' => $signature['logOnly'],
                    'createdAt' => $signature['createdAt'],
                    'category' => $signature['category'],
                );
            }

            $chunks = array_chunk($importedSignatures, 124); // SQLite allows 999 variables in a single query so we chunk accordingly
            foreach ($chunks as $chunk) {
                Signature::query()->insert($chunk); // Batch insert each chunk
            }

            StatusHelper::add(1, 'info', "Loaded " . count($importedSignatures) . " malware signatures");

        } else {
            StatusHelper::add(1, 'info', "Unable to decode the signatures received from Astra API: " . json_encode($signatures));
        }
    }

    public static function logPeakMemory()
    {
        $oldPeak = ConfigHelper::get('peakMemory', 0);
        $peak = memory_get_peak_usage(true);
        if ($peak > $oldPeak) {
            ConfigHelper::set('peakMemory', $peak, "no");
            return $peak;
        }
        return $oldPeak;
    }

    public static function shutdown()
    {
        self::logPeakMemory();
    }

    public static function error_handler($errno, $errstr, $errfile, $errline)
    {
        if (error_reporting() > 0) {
            if (preg_match('/astra\//', $errfile)) {
                $level = 1;
            } else {
                $level = 4;
            }
            StatusHelper::add($level, 'error', "$errstr ($errno) File: $errfile Line: $errline");
        }
        return false;
    }


    protected static function checkCronKey($receivedCronKey)
    {
        StatusHelper::add(4, 'info', "Scan engine received request.");

        StatusHelper::add(4, 'info', "Fetching stored cronkey for comparison.");

        $expired = false;
        $storedCronKey = self::storedCronKey($expired);

        $displayCronKey_received = (isset($receivedCronKey) ? (preg_match('/^[a-f0-9]+$/i', $receivedCronKey) && strlen($receivedCronKey) == 32 ? $receivedCronKey : '[invalid]') : '[none]');
        $displayCronKey_stored = (!empty($storedCronKey) && !$expired ? $storedCronKey : '[none]');

        StatusHelper::add(4, 'info', sprintf('Checking cronkey: %s (expecting %s)', $displayCronKey_received, $displayCronKey_stored));

        if (empty($receivedCronKey)) {
            StatusHelper::add(4, 'error', "Malware scan script accessed directly, or a cronkey was not received.");
            echo "If you see this message it means that the Malware Scanner is working correctly. You should not access this URL directly. It is part of the Astra security Suite and is designed for internal use only.";
            exit();
        }

        if ($expired) {
            self::errorExit("The key used to start a scan expired. The value is: " . $expired . " and split is: " . $storedCronKey . " and time is: " . time());
        } //keys only last 60 seconds and are used within milliseconds of creation

        if (!$storedCronKey) {
            StatusHelper::add(4, 'error', "Astra could not find a saved cron key to start the scan so assuming it started and exiting.");
            exit();
        }

        StatusHelper::add(4, 'info', "Checking saved cronkey against cronkey param");
        if (!\hash_equals($storedCronKey, $receivedCronKey)) {
            self::errorExit("Astra could not start a scan because the cron key does not match the saved key. Saved: " . $storedCronKey . " Sent: " . $receivedCronKey . " Current unexploded: " . ConfigHelper::get('currentCronKey', false));
        }
        ConfigHelper::set('currentCronKey', '');

        return true;
    }

    private static function storedCronKey(&$expired = null)
    {
        $currentCronKey = ConfigHelper::get('currentCronKey', false);
        if (empty($currentCronKey)) {
            if ($expired !== null) {
                $expired = false;
            }
            return false;
        }

        $savedKey = explode(',', $currentCronKey);
        if (time() - $savedKey[0] > 86400) {
            if ($expired !== null) {
                $expired = $savedKey[0];
            }
            return $savedKey[1];
        }

        if ($expired !== null) {
            $expired = false;
        }
        return $savedKey[1];
    }

    private static function errorExit($msg)
    {
        StatusHelper::add(1, 'error', "Scan Engine Error: $msg");
        echo $msg;
        exit();
    }

}