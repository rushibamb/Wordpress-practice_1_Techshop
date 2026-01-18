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

use GetAstra\Helpers\CommonHelper;
use GetAstra\Plugins\Scanner\Helpers\ConfigHelper;
use GetAstra\Plugins\Scanner\Helpers\MalwareHelper;
use GetAstra\Plugins\Scanner\Helpers\ServerHelper;
use GetAstra\Plugins\Scanner\Helpers\StatusHelper;
use GetAstra\Plugins\Scanner\Models\Issue;
use GetAstra\Plugins\Scanner\Models\KnownFile;
use GetAstra\Plugins\Scanner\Models\Signature;

class FileScanner
{

    const EXCLUSION_PATTERNS_ALL = PHP_INT_MAX;
    const EXCLUSION_PATTERNS_USER = 0x1;
    const EXCLUSION_PATTERNS_KNOWN_FILES = 0x2;
    const EXCLUSION_PATTERNS_MALWARE = 0x4;


    protected $path = '';
    protected $results = array();
    public $errorMsg = false;
    protected $backtrackLimit = false;

    protected $totalFilesScanned = 0;
    protected $startTime = false;
    protected $lastStatusTime = false;
    protected $patterns = array();
    protected $patternsMax = 0;
    protected $knownFiles = array();

    protected static $excludePatterns = array();
    protected static $builtinExclusions = array(
        array('pattern' => 'wp\-includes\/version\.php', 'include' => self::EXCLUSION_PATTERNS_KNOWN_FILES), //Excluded from the known files scan because non-en_US installations will have extra content that fails the check, still in malware scan
        array('pattern' => '(?:wp\-includes|wp\-admin)\/(?:[^\/]+\/+)*(?:\.htaccess|\.htpasswd|php_errorlog|error_log|[^\/]+?\.log|\._|\.DS_Store|\.listing|dwsync\.xml)', 'include' => self::EXCLUSION_PATTERNS_KNOWN_FILES),
    );

    protected $scanEngine;


    public function __construct($path, $scanEngine)
    {

        if ($path[strlen($path) - 1] != '/') {
            $path .= '/';
        }

        $this->path = $path;
        $this->scanEngine = $scanEngine;
        $this->patternsMax = Signature::max('sig_id');


        $this->results = array();
        $this->errorMsg = false;


        $this->patterns = array();

        $this->setupSigs();

    }

    protected function setupSigs()
    {
        $sigs = Signature::query()->get();
        $patterns = array();

        foreach ($sigs as $sig) {
            $pattern = $sig->pattern;
            if (@preg_match('/' . $pattern . '/iS', null) === false) {
                StatusHelper::add(1, 'error', 'A regex from DB is invalid. The pattern is: ' . htmlspecialchars($pattern));
            } else {
                $patterns[$sig->sig_id] = $sig;
            }
        }


        $this->patterns['rules'] = $patterns;
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

    public function scan($engine)
    {
        set_error_handler('GetAstra\Plugins\Scanner\Services\FileScanner::error_handler', E_ALL ^ E_DEPRECATED);

        $this->scanEngine = $engine;

        $knownFiles = array();
        foreach (KnownFile::query()->get() as $key => $kFile) {
            $knownFiles[$kFile->path] = $kFile;
        }

        $this->knownFiles = $knownFiles;

        if (!$this->startTime) {
            $this->startTime = microtime(true);
        }

        $this->lastStatusTime = (float)ConfigHelper::get('fileScannerlastStatusTime', 0);
        if (!$this->lastStatusTime) {
            $this->lastStatusTime = microtime(true);
            ConfigHelper::set('fileScannerlastStatusTime', $this->lastStatusTime);
        }

        $this->backtrackLimit = $this->setBacktrackLimit();

        /* File Scanner */
        $lastCount = 'whatever';


        $remainingFileCount = MalwareHelper::countRemaining();
        StatusHelper::add(1, 'info', 'Files to be scanned: ' . $remainingFileCount);
        if(ConfigHelper::get('totalFiles', 0) === 0) {
            ConfigHelper::set('totalFiles', $remainingFileCount);
        }
        ConfigHelper::set('remainingFiles', $remainingFileCount);


        /*if ($thisCount == $lastCount) {
            //count should always be decreasing. If not, we're in an infinite loop so lets catch it early
            StatusHelper::add(4, 'info', 'Detected loop in malware scan, aborting.');
            break;
        }
        $lastCount = $thisCount;*/

        $files = MalwareHelper::files(200);


        if (count($files) < 1) {
            StatusHelper::add(4, 'info', 'No files remaining for malware scan');
            return true;
        }

        foreach ($files as $record) {
            $this->processFile($record);
        }

        /* End of File Scanner */

    }

    private function processFile($record)
    {
        $file = $record->filePath;
        //sleep(1);
        //StatusHelper::add('10', 'error', $file);

        if (!file_exists($this->path . $file)) {
            MalwareHelper::markComplete($record, 0);
            return;
        }
        $fileSum = $record->newMD5;

        $fileExt = '';
        if (preg_match('/\.([a-zA-Z\d\-]{1,7})$/', $file, $matches)) {
            $fileExt = strtolower($matches[1]);
        }
        $isPHP = false;
        if (preg_match('/\.(?:php(?:\d+)?|phtml)(\.|$)/i', $file)) {
            $isPHP = true;
        }
        $isHTML = false;
        if (preg_match('/\.(?:html?)(\.|$)/i', $file)) {
            $isHTML = true;
        }
        $isJS = false;
        if (preg_match('/\.(?:js|svg)(\.|$)/i', $file)) {
            $isJS = true;
        }


        $isScanImagesFile = false;
        if (!$isPHP && preg_match('/^(?:jpg|jpeg|mp3|avi|m4v|mov|mp4|gif|png|tiff?|svg|sql|js|tbz2?|bz2?|xz|zip|tgz|gz|tar|log|err\d+)$/', $fileExt)) {
            if (!$isJS) {
                MalwareHelper::markComplete($record);
                return;
            }
        }

        $isHighSensitivityFile = false;
        if (strtolower($fileExt) == 'sql') {
            MalwareHelper::markComplete($record);
            return;
        }


        if (ServerHelper::fileTooBig($this->path . $file)) {
            StatusHelper::add(2, 'error', sprintf('Encountered file that is too large: %s - Skipping.', $file));
            MalwareHelper::markComplete($record);
            return;
        }

        // We have begun file scanning

        $fsize = @filesize($this->path . $file); //Checked if too big above
        $fsize = ServerHelper::formatBytes($fsize);

        /*
        if (function_exists('memory_get_usage')) {
            StatusHelper::add(4, 'info', sprintf('Scanning contents: %s (Size: %s Mem: %s)', $file, $fsize, ServerHelper::formatBytes(memory_get_usage(true))));
        } else {
            StatusHelper::add(4, 'info', sprintf('Scanning contents: %s (Size: %s)', $file, $fsize));
        }
        */


        $stime = microtime(true);
        $fh = @fopen($this->path . $file, 'r');
        if (!$fh) {
            MalwareHelper::markComplete($record);
            return;
        }

        $totalRead = 0;

        $regexMatchedGlobal = false;
        while (!feof($fh)) {
            $data = fread($fh, 1 * 1024 * 1024); //read 1 megs max per chunk
            $readSize = ServerHelper::strlen($data);
            $currentPosition = $totalRead;
            $totalRead += $readSize;
            if ($readSize < 1) {
                break;
            }

            $extraMsg = "";
            $treatAsBinary = ($isPHP || $isHTML);

            $regexMatched = false;
            $stoppedOnSignature = (int) $record->stoppedOnSignature;

            foreach ($this->patterns['rules'] as $rule) {

                $stoppedOnSignature = $record->stoppedOnSignature;
                if (!empty($stoppedOnSignature) && $stoppedOnSignature !== 0 && $record->isSafeFile !== 'n') { //Advance until we find the rule we stopped on last time
                    if ($stoppedOnSignature == $rule->sig_id) {
                        MalwareHelper::updateStoppedOn($record, '0');
                        $record->stoppedOnSignature = 0;
                        //StatusHelper::add(4, 'info', sprintf('Resuming malware scan at rule %s.', $rule->sig_id));
                    }
                    continue;
                }

                $type = (isset($rule->scanType) && !empty($rule->scanType)) ? $rule->scanType : 'server';

                $logOnly = (isset($rule->logOnly) && !empty($rule->logOnly)) ? $rule->logOnly : false;
                //$commonStringIndexes = (isset($rule[8]) && is_array($rule[8])) ? $rule[8] : array();

                $customMessage = isset($rule->name) ?  "The file was flagged as <strong>" . $rule->name . "</strong> and appears to be created by a hacker with malicious intent. If you know about this file you can choose to ignore it to exclude it from future scans." : 'This file appears to be created by hacker to perform malicious activity. If you know about this file you can choose to ignore it to exclude it from future scans.';
                if ($type == 'server' && !$treatAsBinary) {
                    continue;
                } else if (($type == 'both' || $type == 'browser') && $isJS) {
                    $extraMsg = '';
                } else if (($type == 'both' || $type == 'browser') && !$treatAsBinary) {
                    continue;
                }


                if (preg_match('/(' . $rule->pattern . ')/iS', $data, $matches, PREG_OFFSET_CAPTURE)) {
                    $matchString = $matches[1][0];
                    $matchOffset = $matches[1][1];
                    $beforeString = ServerHelper::substr($data, max(0, $matchOffset - 100), $matchOffset - max(0, $matchOffset - 100));
                    $afterString = ServerHelper::substr($data, $matchOffset + strlen($matchString), 100);
                    if (!$logOnly) {
                        //MalwareHelper::markUnsafe($record);

                        $dataForFile = $this->dataForFile($file);

                        $this->addResult(array(
                            'type' => 'file',
                            'severity' => 'critical',
                            'path' => $this->path . $file,
                            'ignorePath' => md5($this->path . $file),
                            'ignoreChecksum' => $fileSum,
                            'shortMsg' => 'Possible malware: ' . htmlspecialchars($file),
                            'longMsg' => $customMessage . ' ' . '<br/><br/>The malicious text in this file is:' . ' ' . '<br/><code>' . ServerHelper::potentialBinaryStringToHTML((ServerHelper::strlen($matchString) > 200 ? ServerHelper::substr($matchString, 0, 200) . '...' : $matchString)) . '</code>' . '<br><br>' . sprintf('<strong>Issue type:</strong> %s', htmlspecialchars($rule->category)) . '<br>' . sprintf('<strong>Description: </strong> %s', htmlspecialchars($rule->description)) . $extraMsg,
                            'data' => array_merge(array(
                                'file' => $file,
                            ), $dataForFile),
                        ));

                        StatusHelper::add('10', 'malware', 'Malware - ' . $file);
                        MalwareHelper::markCompleteDetection($record, $rule->sig_id);

                    }
                    $regexMatched = true;
                    $regexMatchedGlobal = true;
                    //$this->scanEngine->recordMetric('malwareSignature', $rule[0], array('file' => $file, 'match' => $matchString, 'before' => $beforeString, 'after' => $afterString, 'md5' => $record->newMD5, 'shac' => $record->SHAC), false);
                    break;
                }

                if ($this->scanEngine->shouldFork()) {
                    MalwareHelper::updateStoppedOn($record, $this->patternsMax);
                    fclose($fh);

                    StatusHelper::add(4, 'info', sprintf('Forking during malware scan (%s) to ensure continuity.', $rule->sig_id));
                    $this->scanEngine->fork(); //exits
                }

            }




            if ($regexMatched) {
                break;
            }


            if ($totalRead > 2 * 1024 * 1024) {
                break;
            }
        }


        fclose($fh);

        /*

        */

        $this->totalFilesScanned++;


        if (microtime(true) - $this->lastStatusTime > 1) {
            $this->lastStatusTime = microtime(true);
            $this->writeScanningStatus();
        }


        $isSafeFile = '';
        if ($record->isSafeFile == 'n' && !$regexMatchedGlobal) { // Mark a previously flagged file as safe if it no longer matches a malware signature
            $isSafeFile = 'y';
        }

        MalwareHelper::markComplete($record, $this->patternsMax, $isSafeFile);

        $this->scanEngine->forkIfNeeded();

        if ($this->backtrackLimit !== false) {
            ini_set('pcre.backtrack_limit', $this->backtrackLimit);
        }
        return $this->results;
    }

    protected function writeScanningStatus()
    {
        $rate = ($this->totalFilesScanned / (microtime(true) - $this->startTime));
        StatusHelper::add(2, 'info', sprintf('Scanned contents of %d additional files at %.2f per second', $this->totalFilesScanned, $rate));
        ConfigHelper::set('fileRate', $rate);
    }

    protected function addResult($result)
    {
        for ($i = 0; $i < sizeof($this->results); $i++) {
            if ($this->results[$i]['type'] == 'file' && $this->results[$i]['data']['file'] == $result['data']['file']) {
                if ($this->results[$i]['severity'] > $result['severity']) {
                    $this->results[$i] = $result; //Overwrite with more severe results
                }
                return;
            }
        }

        $deleteKey = CommonHelper::bigRandomHex();

        Issue::addIssue(
            $result['type'],
            $result['severity'],
            $result['path'],
            $result['ignorePath'],
            $result['ignoreChecksum'],
            $result['shortMsg'],
            $deleteKey,
            $result['longMsg'],
            $result['data'],
            true
        );

        //We don't have a results for this file so append
        $this->results[] = $result;
    }

    private function setBacktrackLimit()
    {
        $backtrackLimit = ini_get('pcre.backtrack_limit');
        if (is_numeric($backtrackLimit)) {
            $backtrackLimit = (int)$backtrackLimit;
            if ($backtrackLimit > 10000000) {
                ini_set('pcre.backtrack_limit', 1000000);
                StatusHelper::add(4, 'info', sprintf('Backtrack limit is %d, reducing to 1000000', $backtrackLimit));
            }
        } else {
            $backtrackLimit = false;
        }

        return $backtrackLimit;
    }

    private function dataForFile($file, $fullPath = null)
    {

        $data = array();

        $isKnownFile = false;
        if (array_key_exists($file, $this->knownFiles)) {
            $isKnownFile = true;
            $data['cType'] = 'core';
        }


        $data['canDiff'] = $isKnownFile;
        $data['canFix'] = $isKnownFile;
        $data['canDelete'] = !$isKnownFile;

        return $data;
    }


}