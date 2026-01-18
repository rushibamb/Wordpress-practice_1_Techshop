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

namespace GetAstra\Helpers;


class UrlHelper
{

    public static function getCurrentUri($params = NULL, $no_trailing_slash = TRUE)
    {

        // http(s)://domain.com
        $url = @$_SERVER['HTTPS'] == 'on' || @$_SERVER['HTTP_X_FORWARDED_SSL'] == 'on' ? 'https://' . $_SERVER['SERVER_NAME'] : 'http://' . $_SERVER['SERVER_NAME'];

        // add the port number, if there is one
        if (@$_SERVER['SERVER_PORT'] != "80" && @$_SERVER['SERVER_PORT'] != "443") $url .= ':' . @$_SERVER['SERVER_PORT'];

        // Append the query string
        $url .= $_SERVER['REQUEST_URI'];

        // [optionally] remove the trailing slash if there is one
        if ($no_trailing_slash) $url = rtrim($url, '/');

        // Add any additional parameters that may have been included
        if ($params) $url .= $params;

        return $url;
    }
}