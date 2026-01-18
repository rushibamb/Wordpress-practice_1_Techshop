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
 * @date   2019-03-24
 */

namespace GetAstra\Plugins\Scanner\Models;

use GetAstra\Plugins\Scanner\Helpers\ScanRelayHelper;
use Illuminate\Database\Eloquent\Model;
use \DateTime;

class Issue extends Model
{
    //public $timestamps = false;

    protected $casts = [
        'data' => 'array',
    ];

    public static function addIssue($type, $severity, $path, $ignorePath, $ignoreChecksum, $shortMsg, $deleteKey, $longMsg, $templateData, $fileContents = false)
    {

        $data = array(
            'type' => $type,
            'severity' => $severity,
            'path' => $path,
            'ignorePath' => $ignorePath,
            'ignoreChecksum' => $ignoreChecksum,
            'shortMsg' => $shortMsg,
            'deleteKey' => $deleteKey,
            'longMsg' => $longMsg,
            'data' => json_encode($templateData),
            'fileContents' => $fileContents ? mb_convert_encoding(file_get_contents($path,FALSE,NULL,0,1048576), 'UTF-8', 'UTF-8') : '',
            'status' => 'new',
            'created_at' => new DateTime(),
            'updated_at' => new DateTime(),
        );

        $relay = new ScanRelayHelper();
        $relay->addIssue($data);

        return Issue::insert($data);
    }
}