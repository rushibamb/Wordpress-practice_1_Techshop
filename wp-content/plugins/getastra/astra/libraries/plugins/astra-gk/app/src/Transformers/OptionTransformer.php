<?php

namespace GetAstra\Transformers;

use GetAstra\Models\Option;
use League\Fractal\TransformerAbstract;

class OptionTransformer extends TransformerAbstract
{

    /**
     * @var integer|null
     */
    protected $requestUserId;

    /**
     * OptionTransformer constructor.
     *
     */
    public function __construct()
    {
    }

    public function transform(Option $option)
    {
        return [
            "name" => $option->name,
            "val" => $option->val,
            "group" => $option->group,
            "autoload" => $option->autoload,
        ];
    }


}