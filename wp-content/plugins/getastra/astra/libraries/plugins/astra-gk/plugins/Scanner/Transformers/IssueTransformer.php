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
 * @date   2019-03-25
 */

namespace GetAstra\Plugins\Scanner\Transformers;

use League\Fractal\TransformerAbstract;
use GetAstra\Plugins\Scanner\Models\Issue;

class IssueTransformer extends TransformerAbstract
{

    /**
     * IssueTransformer constructor.
     *
     */
    public function __construct()
    {
    }

    public function transform(Issue $issue)
    {
        return [
            'type' => $issue->type,
            'severity' => $issue->severity,
            'path' => $issue->path,
            'ignorePath' => $issue->ignorePath,
            'ignoreChecksum' => $issue->ignoreChecksum,
            'shortMsg' => $issue->shortMsg,
            'longMsg' => $issue->longMsg,
            'data' => $issue->templateData,
            'status' => $issue->status,
        ];

    }


}