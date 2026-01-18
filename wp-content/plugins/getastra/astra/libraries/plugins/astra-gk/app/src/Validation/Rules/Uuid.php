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
 * @date   2019-03-31
 */

namespace GetAstra\Validation\Rules;

use Respect\Validation\Rules\AbstractRule;

class Uuid extends AbstractRule
{
    public function validate($input)
    {
        if (!is_string($input) || (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $input) !== 1)) {
            return false;
        }

        return true;
    }
}