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
 * @date   2019-03-14
 */

namespace GetAstra\Plugins\Scanner\Services;

use GetAstra\Helpers\DBHelper;
use GetAstra\Helpers\UrlHelper;
use GetAstra\Plugins\Scanner\Helpers\ConfigHelper;
use GetAstra\Plugins\Scanner\Helpers\MalwareHelper;
use GetAstra\Plugins\Scanner\Helpers\ScanRelayHelper;
use GetAstra\Plugins\Scanner\Helpers\ServerHelper;
use GetAstra\Plugins\Scanner\Helpers\StatusHelper;
use GetAstra\Helpers\CommonHelper;
use \Curl\MultiCurl;

class ScanEngine
{

    private $forkRequested = false;

    private $hasher = false;
    private $startTime = 0;
    private $cycleStartTime = 0;
    public $maxExecTime = false;

    private $scanner = false;
    private $scanQueue = array();

    private $hoover = false;
    private $scanData = array();

    private $malwarePrefixesHash = array();
    private $coreHashesHash = array();

    private $forkCount = 0;

    private $metrics = array();
    private $jobList = array();

    public function __construct($malwarePrefixesHash = '', $coreHashesHash = '')
    {
        $this->startTime = time();
        $this->recordMetric('scan', 'start', $this->startTime);
        $this->maxExecTime = self::getMaxExecutionTime();
        $this->cycleStartTime = time();

        $this->malwarePrefixesHash = $malwarePrefixesHash;
        $this->coreHashesHash = $coreHashesHash;

        $this->jobList = array();
        $jobList = ConfigHelper::get('jobList', array());

        if (empty($jobList)) {
            $jobs = $this->jobs();
            foreach ($jobs as $job) {
                if (method_exists($this, 'scan_' . $job . '_init')) {
                    foreach (array('init', 'main', 'finish') as $op) {
                        $this->jobList[] = $job . '_' . $op;
                    }
                } else if (method_exists($this, 'scan_' . $job)) {
                    $this->jobList[] = $job;
                }
            }

            ConfigHelper::set('jobList', $this->jobList);
        } else {
            $this->jobList = $jobList;
        }


    }

    public static function startScan($isFork = false)
    {
        if (!defined('DONOTCACHEDB')) {
            define('DONOTCACHEDB', true);
        }

        if (!$isFork) {
            // It means that the scan is being initiated now.

            ConfigHelper::increment('totalScansRun');
            ConfigHelper::set('scanDuration', 0); // Total time taken to run the scan
            ConfigHelper::set('killRequested', 0);

            StatusHelper::add(4, 'info', "Entering start scan routine");

            if (self::isRunning()) {
                StatusHelper::add(1, 'info', "A scan is already running. Use the stop scan button if you would like to terminate the current scan.");
            }

            ConfigHelper::set('currentCronKey', ''); //Ensure the cron key is cleared
        }

        $timeout = self::getMaxExecutionTime() - 2; //2 seconds shorter than max execution time which ensures that only 2 HTTP processes are ever occupied

        $testResult = '';
        if (!ConfigHelper::get('startScansRemotely', false)) {
            try {
                $baseUrl = ConfigHelper::get('baseUrl', '');
                $testResult = AjaxService::textAjax($baseUrl, $timeout);
            } catch (Exception $e) {
                //Fall through to the remote start test below
            }

            StatusHelper::add(4, 'info', "Test result of scan start URL fetch: " . var_export($testResult, true));
        }

        $cronKey = CommonHelper::bigRandomHex();
        ConfigHelper::set('currentCronKey', time() . ',' . $cronKey);

        /* Will be starting the scan */
        if ((!empty($testResult)) && strstr($testResult, 'SCANTESTOK') !== false) {
            //ajax requests can be sent by the server to itself

            $baseUrl = ConfigHelper::get('baseUrl');
            if (isset($_GET['route'])) {
                $cronURL = '/do&isFork=' . ($isFork ? '1' : '0') . '&cronKey=' . $cronKey;
            } else {
                $cronURL = '/do?isFork=' . ($isFork ? '1' : '0') . '&cronKey=' . $cronKey;
            }

            $cronURL = $baseUrl . $cronURL;

            StatusHelper::add(4, 'info', "Starting cron with normal ajax at URL $cronURL");

            try {
                ConfigHelper::set('scanStartAttemptscanStartAttempt', time());

                $multiCurl = new MultiCurl();
                $multiCurl->setOpt(CURLOPT_SSL_VERIFYHOST, false);
                $multiCurl->setOpt(CURLOPT_SSL_VERIFYPEER, false);
                //$multiCurl->setRetry(3);
                //$multiCurl->setHeader('Referer', false);
                $multiCurl->setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36');
                $multiCurl->setReferrer('https://www.getastra.com/?scanfork');


                // $multiCurl->setOpt(CURLOPT_TIMEOUT_MS, 10);
                $multiCurl->setTimeout(3);

                $multiCurl->addGet($cronURL);

                //TODO Notify SF about Scan Start
            } catch (\Exception $e) {
                ConfigHelper::set('lastScanCompleted', $e->getMessage());
                ConfigHelper::set('lastScanFailureType', 'scanner.callbackfailed');
                return false;
            }

            $multiCurl->error(function ($instance) {
                $error_message = $instance->errorCode . ': ' . $instance->errorMessage;
                ConfigHelper::set('lastScanCompleted', "There was an " . ($error_message ? '' : 'unknown ') . "error starting the scan" . ($error_message ? ": $error_message" : '.'));
                ConfigHelper::set('lastScanFailureType', 'scanner.callbackfailed');

                if ($instance->errorCode !== CURLE_OPERATION_TIMEDOUT) {
                    $relay = new ScanRelayHelper();
                    $message = 'Error (' . $instance->errorCode . ') while forking: ' . $error_message;
                    $message = strlen($message) > 255 ? substr($message, 0, 222) . "..." : $message;

                    $relay->sendScanStatus('failed', $message);
                }

            });

            $multiCurl->complete(function ($instance) {
                $message = "";
                if (method_exists($instance, 'response')) {
                    $message = $instance->response;
                }
                StatusHelper::add(4, 'info', "Scan MultiCurl completed for " . $instance->url . " with response " . $message);
            });

            /*
            $multiCurl->success(function ($instance) {
                StatusHelper::add(4, 'info', "Scan MultiCurl success with message");
            });
            */

            $multiCurl->start();
            StatusHelper::add(4, 'info', "Scan process ended after forking.");
        } else {
            // Was unable to run the scan via cUrl to remotely start scan

            $relay = new ScanRelayHelper();
            $relay->sendScanStatus('failed', 'Error while testing ajax: ' . $testResult.'; triggering remote request.');
            ConfigHelper::set('scanRequireRemoteStart', time());
            ConfigHelper::set('startScansRemotely', true);
            $relay->sendBounceRequest($cronKey, $isFork, ConfigHelper::get('scanCode'));
            StatusHelper::add(4, 'info', 'Remote scan request placed');
        }

        return false;
    }

    public static function requestKill()
    {
        ConfigHelper::set('killRequested', time(), "no");
    }

    public static function checkForKill()
    {
        $kill = (int)ConfigHelper::get('killRequested', 0);
        $math = (time() - strtotime(date('m/d/Y H:i:s', $kill))) < 600; //Kill lasts for 10 minutes
        if ($kill !== 0 && $math) {
            StatusHelper::add(10, 'info', "Kill and math: " . json_encode(array($kill, $math)));
            ConfigHelper::set('killRequested', 0);
            StatusHelper::add(10, 'info', "Previous scan was stopped successfully. Scan was stopped on administrator request");
            exit();
        }
    }

    /**
     * Returns whether or not a scan is running. A scan is considered running if the timestamp
     * under 'scanRunning' is within limits defined
     *
     * @return bool
     */
    public static function isRunning()
    {
        $scanRunning = (int)ConfigHelper::get('scanRunning');
        $scanTimeout = (int)ConfigHelper::get('scanTimeoutMinutes');

        /*
        echo "ScanRunning: " . date('m/d/Y H:i:s', $scanRunning) . "\r\n";
        echo "Time Now: " . date('m/d/Y H:i:s', time()) . "\r\n";
        echo "Difference: " . (time() - strtotime(date('m/d/Y H:i:s', $scanRunning))) . "\r\n";
        echo "Timeout: " . ($scanTimeout * 60);
        die();
        */

        $timeoutCrossed = (time() - strtotime(date('m/d/Y H:i:s', $scanRunning))) < ($scanTimeout * 60);

        return $scanRunning && $timeoutCrossed;
    }

    public static function getMaxExecutionTime($staySilent = false)
    {
        $config = ConfigHelper::get('maxExecutionTime');
        $scanMinExecTime = 8;
        $scanMaxIniExecTime = 90;

        if (is_numeric($config) && $config >= $scanMinExecTime) {
            if (!$staySilent) {
                StatusHelper::add(4, 'info', "getMaxExecutionTime() returning config value: $config");
            }
            return $config;
        }

        $ini = @ini_get('max_execution_time');
        if (!$staySilent) {
            StatusHelper::add(4, 'info', "Got max_execution_time value from ini: $ini");
        }
        if (is_numeric($ini) && $ini >= $scanMinExecTime) {
            if ($ini > $scanMaxIniExecTime) {
                if (!$staySilent) {
                    StatusHelper::add(4, 'info', "ini value of {$ini} is higher than value for $scanMaxIniExecTime (" . $scanMaxIniExecTime . "), reducing");
                }
                $ini = $scanMaxIniExecTime;
            }

            $ini = floor($ini / 2);
            if (!$staySilent) {
                StatusHelper::add(4, 'info', "getMaxExecutionTime() returning half ini value: $ini");
            }
            return $ini;
        }

        if (!$staySilent) {
            StatusHelper::add(4, 'info', "getMaxExecutionTime() returning default of: 15");
        }
        return 15;
    }

    public function lastScanTime()
    {
        return ConfigHelper::get('scanTime');
    }

    public function recordLastScanTime()
    {
        ConfigHelper::set('scanTime', microtime(true));
    }

    public static function storeState()
    {
        return true;
    }

    public function shouldFork()
    {
        static $lastCheck = 0;

        if (time() - $this->cycleStartTime > $this->maxExecTime) {
            return true;
        }

        if ($lastCheck > time() - $this->maxExecTime) {
            return false;
        }

        $lastCheck = time();

        ConfigHelper::updateScanStillRunning();
        self::checkForKill();
        $this->checkForDurationLimit();

        return false;
    }

    public function forkIfNeeded()
    {
        ConfigHelper::updateScanStillRunning();
        self::checkForKill();
        $this->checkForDurationLimit();
        if (time() - $this->cycleStartTime > $this->maxExecTime) {
            StatusHelper::add(4, 'info', "Forking during hash scan to ensure continuity.");
            $this->fork();
        }
    }

    public function fork()
    {
        StatusHelper::add(4, 'info', "Entered fork()");
        if (self::storeState()) {
            //$this->scanController->flushSummaryItems();
            StatusHelper::add(4, 'info', "Calling startScan(true)");
            self::startScan(true);
        } //Otherwise there was an error so don't start another scan.
        exit(0);
    }

    public function doScan()
    {

        StatusHelper::add(4, 'info', "Doing Scan");

        while (sizeof($this->jobList) > 0) {
            self::checkForKill();
            $jobFinished = false;

            $jobName = $this->jobList[0];
            $callback = array($this, 'scan_' . $jobName);

            if (is_callable($callback)) {
                StatusHelper::add("3", "info", "Dispatching job: scan_$jobName");
                $jobFinished = call_user_func($callback);
            }

            if ($jobFinished === true) {
                array_shift($this->jobList); //only shift once we're done because we may pause halfway through a job and need to pick up where we left off
            }

            ConfigHelper::set('jobList', $this->jobList);

            self::checkForKill();
            if ($this->forkRequested) {
                $this->fork();
            } else {
                $this->forkIfNeeded();
            }
        }

        /* End */

        $startTime = (int)ConfigHelper::get('startTime');
        $scanDuration = (time() - $startTime) / 60;

        ConfigHelper::set('scanDuration', $scanDuration);
        ConfigHelper::set('startScansRemotely', false);
        StatusHelper::add("2", "info", "Scan completed in " . $scanDuration . " min at " . date('m/d/Y H:i:s', time()));

        $relay = new ScanRelayHelper();
        $relay->sendMetrics();

        //DBHelper::vacuumDB();

        return;
    }

    public function removeJob($name = '')
    {

        if (empty($name)) {
            array_shift($this->jobList);
        }

        ConfigHelper::set('jobList', $this->jobList);
    }

    public function deleteNewIssues($types = null)
    {
        $this->issues->deleteNew($types);
    }

    public function go()
    {
        try {
            self::checkForKill();
            $this->doScan();
            ConfigHelper::set('lastScanCompleted', 'ok');
            ConfigHelper::set('lastScanFailureType', false);
            self::checkForKill();

            //updating this scan ID will trigger the scan page to load/reload the results.
            //$this->scanController->recordLastScanTime();
            //scan ID only incremented at end of scan to make UI load new results
            //$this->emailNewIssues();

            // Record Metrics about the scan
            $this->recordMetric('scan', 'duration', (time() - $this->startTime));
            $this->recordMetric('scan', 'memory', ConfigHelper::get('peakMemory', 0, false));
            $this->submitMetrics();

            //TODO Notify SF about Scan status
        } catch (\Exception $e) {
            StatusHelper::add(5, 'error', 'Scan error: ' . $e->getMessage());
            ConfigHelper::set('lastScanCompleted', $e->getMessage());
            ConfigHelper::set('lastScanFailureType', "scanner.general");
        }
    }

    public function submitMetrics()
    {
        if (ConfigHelper::get('shareMetrics', true)) {
            //TODO Send Metrics to SF
        }
    }

    public function recordMetric($type, $key, $value, $singular = true)
    {
        if (!isset($this->metrics[$type])) {
            $this->metrics[$type] = array();
        }

        if (!isset($this->metrics[$type][$key])) {
            $this->metrics[$type][$key] = array();
        }

        if ($singular) {
            $this->metrics[$type][$key] = $value;
        } else {
            $this->metrics[$type][$key][] = $value;
        }
    }

    public function checkForDurationLimit()
    {
        static $timeLimit = false;
        if ($timeLimit === false) {
            $timeLimit = intval(ConfigHelper::get('scanMaxDuration', 0));
            if ($timeLimit < 1) {
                //$timeLimit = 10800; // Default maxScanDuration
                $timeLimit = 10800; // Default maxScanDuration
            }
        }

        $startTime = (int)ConfigHelper::get('startTime');

        if ((time() - $startTime) > $timeLimit) {
            $error = 'The scan time limit of ' . StatusHelper::makeDuration($timeLimit) . ' has been exceeded and the scan will be terminated. This limit can be customized on the options page.';
            StatusHelper::add(10, 'info', $error);

            $relay = new ScanRelayHelper();
            $relay->sendMetrics();

            exit;

        }
    }

    private function scan_knownFiles_init()
    {


        $baseWPStuff = array('.htaccess', 'index.php', 'license.txt', 'readme.html', 'wp-activate.php', 'wp-admin', 'wp-app.php', 'wp-blog-header.php', 'wp-comments-post.php', 'wp-config-sample.php', 'wp-content', 'wp-cron.php', 'wp-includes', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-pass.php', 'wp-register.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php');
        $baseContents = scandir(ASTRA_DOC_ROOT);

        if (!is_array($baseContents)) {
            throw new \Exception("Astra could not read the contents of your base directory. This usually indicates your permissions are so strict that your web server can't read the website directory.");
        }

        $includeInKnownFilesScan = array();
        $scanOutside = (bool)ConfigHelper::get('scanOutsideFiles', true);

        //echo $scanOutside;

        foreach ($baseContents as $file) { //Only include base files less than a meg that are files.
            if ($file == '.' || $file == '..') {
                continue;
            }
            $fullFile = rtrim(ASTRA_DOC_ROOT, '/') . '/' . $file;

            if ((@is_file($fullFile) || @is_dir($fullFile)) && @is_readable($fullFile) && (!ServerHelper::fileTooBig($fullFile))) {

                if (!$scanOutside && !in_array($file, $baseWPStuff)) {
                    continue;
                }

                $includeInKnownFilesScan[$file] = 1;

            }
        }

        ConfigHelper::set('totalFilesScanned', 0); //Since it's a new scan set the total as zero
        ConfigHelper::set('filesToScan', $includeInKnownFilesScan);

        return true;
    }

    public function test()
    {
        //$this->scan_knownFiles_init();
        //$this->scan_knownFiles_main();
        //$this->scan_knownFiles_finish();
        //$this->scan_fileContents_init();
        $this->scan_fileContents_main();
    }

    private function scan_knownFiles_main()
    {

        $this->hasher = new HasherService(strlen(ASTRA_DOC_ROOT), ASTRA_DOC_ROOT, $this);

        return $this->hasher->run($this);
    }

    private function scan_knownFiles_finish()
    {
        $this->hasher = new HasherService(strlen(ASTRA_DOC_ROOT), ASTRA_DOC_ROOT, $this);

        return $this->hasher->passiveScan($this);
    }


    public function scan_fileContents_init()
    {
        StatusHelper::add(1, 'info', 'Scanning file contents for infections and vulnerabilities');
        ConfigHelper::set('totalFiles', 0);
        return true;
    }

    public function scan_fileContents_main()
    {
        $scanner = new FileScanner(ASTRA_DOC_ROOT, $this);
        return $scanner->scan($this);
        //return true;
    }

    public function scan_fileContents_finish()
    {
        return true;
    }

    public function jobs()
    {
        $preferredOrder = array(
            'knownFiles' => (bool)ConfigHelper::get('scanCheck_knownFiles', true),
            'fileContents' => (bool)ConfigHelper::get('scanCheck_fileContents', true),
            'suspectedFiles' => (bool)ConfigHelper::get('scanCheck_suspectedFiles', true)
        );

        $jobs = array();
        foreach ($preferredOrder as $job => $enabler) {
            if ($enabler === true) {
                $jobs[] = $job;
            }
        }
        return $jobs;
    }

}