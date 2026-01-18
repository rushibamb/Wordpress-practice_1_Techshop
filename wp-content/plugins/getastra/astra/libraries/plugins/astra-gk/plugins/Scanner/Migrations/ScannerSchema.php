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

namespace GetAstra\Plugins\Scanner\Migrations;

use GetAstra\Plugins\Scanner\Helpers\ConfigHelper;
use Interop\Container\ContainerInterface;
use GetAstra\Helpers\OptionsHelper as Options;
use GetAstra\Models\Option as Option;


class ScannerSchema
{

    const AUTOLOAD = 'yes';
    const NOT_AUTOLOAD = 'no';

    /**
     * @var \Interop\Container\ContainerInterface
     */
    private $container;

    /**
     * @var \Illuminate\Database\Schema
     */
    private $schema;

    private $db;

    private $prefix;

    /**
     * HaltResponse constructor.
     *
     * @param \Interop\Container\ContainerInterface $container
     *
     */
    public function __construct(ContainerInterface $container = null)
    {
        $this->container = $container;
        $this->schema = $container->get('schema');
        $this->db = $container->get('db');
    }

    public function exists()
    {
        //$this->dropAllTables();
        return $this->schema->hasTable('scan_status');
    }

    public function runInstall()
    {
        $this->dropAllTables();

        $this->createAllTables();
        $this->seedTables();

    }

    protected function dropAllTables()
    {
        $this->schema->dropIfExists('scans');
        $this->schema->dropIfExists('file_changes');
        $this->schema->dropIfExists('scan_status');
        $this->schema->dropIfExists('link_scanning');
        $this->schema->dropIfExists('file_mods');
        $this->schema->dropIfExists('known_file_list');
        $this->schema->dropIfExists('signatures');
        $this->schema->dropIfExists('indexed_files');
    }

    protected function createAllTables()
    {

        // Scans

        /*
        $this->schema->create('scans', function ($t) {
            $t->bigIncrements('id')->unsigned();
            $t->string('code', 100);
            $t->boolean('isRunning');
            $t->enum('status', ['running', 'completed', 'canceled']);
            $t->nullableTimestamps();
        });
        */

        // Files Changes Table
        $this->schema->create('file_changes', function ($t) {
            $t->char('fileNameHash', 64)->primary();
            $t->string('file', 1000);
            $t->char('md5', 32);
        });

        $this->schema->create('scan_status', function ($t) {
            $t->bigIncrements('id')->unsigned();
            $t->double('ctime', 17, 6)->unsigned();
            $t->tinyInteger('level');
            $t->char('type', 5);
            $t->text('msg');
        });

        /*
        $this->schema->create('link_scanning', function ($t) {
            $t->increments('id')->unsigned();
            $t->text('owner');
            $t->text('host');
            $t->text('path');
            $t->binary('hostKey');

            //$t->index('hostKey');
        });
        */

        $this->schema->create('file_mods', function ($t) {
            $t->string('filenameMD5', 32)->unique();
            $t->text('filePath');
            $t->tinyInteger('knownFile')->unsigned();
            $t->string('oldMD5', 32)->nullable();
            $t->string('newMD5', 32)->nullable();
            //$t->binary('SHAC');
            $t->integer('stoppedOnSignature')->unsigned()->default(0);
            $t->boolean('toScan')->default(true);
            $t->char('isSafeFile', 1)->default('?');
        });

        $this->schema->create('known_file_list', function ($t) {
            $t->increments('id')->unsigned();
            $t->text('path');
            $t->string('md5', 32);
        });

        $this->schema->create('indexed_files', function ($t) {
            //$t->increments('id')->unsigned();
            $t->text('path');
            $t->string('md5', 32);
            $t->string('status', 15)->nullable();

            //$t->index('path');
        });

        $this->schema->create('signatures', function ($t) {
            $t->integer('sig_id')->unsigned();
            $t->dateTime('createdAt');
            $t->text('pattern');
            $t->string('category', 100);
            $t->string('name', 500);
            $t->text('description');
            $t->string('scanType', 20);
            $t->boolean('logOnly');

            $t->index('sig_id');
        });

    }

    protected function seedTables()
    {

        $options = array(
            array('name' => 'ms_scanTimeoutMinutes', 'val' => 15, 'autoload' => self::NOT_AUTOLOAD, 'group' => 'scanner'),

            array('name' => 'maxExecutionTime', 'val' => 0, 'autoload' => self::NOT_AUTOLOAD, 'group' => 'scanner'),
            array('name' => 'minExecutionTime', 'val' => 8, 'autoload' => self::NOT_AUTOLOAD, 'group' => 'scanner'),
            array('name' => 'maxScanLockTime', 'val' => 86400, 'autoload' => self::NOT_AUTOLOAD, 'group' => 'scanner'),
            array('name' => 'maxIniExecutionTime', 'val' => 90, 'autoload' => self::NOT_AUTOLOAD, 'group' => 'scanner'),

            array('name' => 'scanCheck_knownFiles', 'val' => true, 'autoload' => self::NOT_AUTOLOAD, 'group' => 'scanner',),
            array('name' => 'scanCheck_fileContents', 'val' => true, 'autoload' => self::NOT_AUTOLOAD, 'group' => 'scanner',),
            array('name' => 'scanCheck_suspectedFiles', 'val' => true, 'autoload' => self::NOT_AUTOLOAD, 'group' => 'scanner',),

            array('name' => 'scanOutsideFiles', 'val' => false, 'autoload' => self::NOT_AUTOLOAD, 'group' => 'scanner',),
            array('name' => 'scanUnknownCMSFiles', 'val' => false, 'autoload' => self::NOT_AUTOLOAD, 'group' => 'scanner',),
            array('name' => 'lowResourceScansEnabled', 'val' => false, 'autoload' => self::NOT_AUTOLOAD, 'group' => 'scanner',),
            array('name' => 'scan_exclude', 'val' => '', 'autoload' => self::NOT_AUTOLOAD, 'group' => 'scanner',),
            array('name' => 'ms_siteIri', 'val' => '', 'autoload' => self::NOT_AUTOLOAD, 'group' => 'scanner',),
            array('name' => 'ms_scanCode', 'val' => '', 'autoload' => self::NOT_AUTOLOAD, 'group' => 'scanner',),

        );

        //ConfigUtil::set();
        foreach($options as $option){
            Options::set($option['name'], $option['val'], $option['autoload'], 'scanner');
        }

        return true;
    }

}