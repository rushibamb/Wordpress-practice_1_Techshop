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

use \Curl\Curl;
use GetAstra\Helpers\UrlHelper;
use GetAstra\Plugins\Scanner\Helpers\StatusHelper;

class AjaxService
{

    public static function textAjax($baseUrl = '', $timeout = '')
    {

        if (empty($baseUrl)) {
            $baseUrl = UrlHelper::getCurrentUri();
        }

        if (strpos($baseUrl, '/do/testAjax') !== false) {
            $baseUrl = strtok($baseUrl, '?');
            $testUrl = $baseUrl . '/testAjax';
        } else {
            $testUrl = $baseUrl . '/do/testAjax';
        }
        
        $curl = new Curl();
        $curl->setOpt(CURLOPT_SSL_VERIFYHOST, false);
        $curl->setOpt(CURLOPT_SSL_VERIFYPEER, false);
        $curl->setHeader('X-Requested-With', 'XMLHttpRequest');
        $curl->setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36');
        $curl->setReferrer('https://www.getastra.com/?scanfork');
        //$curl->setRetry(3);

        if (!empty($timeout)) {
            $curl->setTimeout($timeout);
        }

        StatusHelper::add(4, 'info', "Test URL: " . var_export($testUrl, true));

        $curl->post($testUrl);

        if ($curl->error) {
            return $curl->errorCode . ': ' . $curl->errorMessage;
        } else {
            return $curl->response;
        }
    }

}