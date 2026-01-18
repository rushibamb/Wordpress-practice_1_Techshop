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
 * @date   2019-03-19
 */

namespace GetAstra\Plugins\Scanner\Controllers\Scan;

use GetAstra\Helpers\Cms\AbstractCmsHelper;
use GetAstra\Helpers\DBHelper;
use GetAstra\Helpers\OptionsHelper;
use GetAstra\Models\Option;
use GetAstra\Plugins\Scanner\Helpers\MalwareHelper;
use GetAstra\Plugins\Scanner\Helpers\ScanRelayHelper;
use GetAstra\Plugins\Scanner\Models\IndexedFile;
use GetAstra\Plugins\Scanner\Models\Scan;
use GetAstra\Plugins\Scanner\Services\ScanEngine;
use GetAstra\Plugins\Scanner\Services\ScanService;

use Interop\Container\ContainerInterface;
use Slim\Http\Request;
use Slim\Http\Response;

class TestController
{

    protected $container;

    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
    }

    public function verifyMalwarePrefixes(Request $request, Response $response, array $args)
    {

        //$jwt = OptionsHelper::get('jwtToken', '', false);
        //echo $jwt; die('<--');

        $engine = new ScanEngine();
        $engine->go();
    }

    public static function hex2bin($hexString, $strictPadding = false)
    {
        /* Type checks: */
        if (!is_string($hexString)) {
            throw new TypeError('Argument 1 must be a string, ' . gettype($hexString) . ' given.');
        }

        /** @var int $hex_pos */
        $hex_pos = 0;
        /** @var string $bin */
        $bin = '';
        /** @var int $c_acc */
        $c_acc = 0;
        /** @var int $hex_len */
        $hex_len = self::strlen($hexString);
        /** @var int $state */
        $state = 0;
        if (($hex_len & 1) !== 0) {
            if ($strictPadding) {
                throw new RangeException(
                    'Expected an even number of hexadecimal characters'
                );
            } else {
                $hexString = '0' . $hexString;
                ++$hex_len;
            }
        }

        $chunk = unpack('C*', $hexString);
        while ($hex_pos < $hex_len) {
            ++$hex_pos;
            /** @var int $c */
            $c = $chunk[$hex_pos];
            /** @var int $c_num */
            $c_num = $c ^ 48;
            /** @var int $c_num0 */
            $c_num0 = ($c_num - 10) >> 8;
            /** @var int $c_alpha */
            $c_alpha = ($c & ~32) - 55;
            /** @var int $c_alpha0 */
            $c_alpha0 = (($c_alpha - 10) ^ ($c_alpha - 16)) >> 8;
            if (($c_num0 | $c_alpha0) === 0) {
                throw new RangeException(
                    'hex2bin() only expects hexadecimal characters'
                );
            }
            /** @var int $c_val */
            $c_val = ($c_num0 & $c_num) | ($c_alpha & $c_alpha0);
            if ($state === 0) {
                $c_acc = $c_val * 16;
            } else {
                $bin .= pack('C', $c_acc | $c_val);
            }
            $state ^= 1;
        }
        return $bin;
    }

}