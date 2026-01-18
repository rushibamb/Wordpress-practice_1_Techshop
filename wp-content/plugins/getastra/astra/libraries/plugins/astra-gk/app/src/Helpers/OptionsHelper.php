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
 * @date   2019-03-11
 */

namespace GetAstra\Helpers;

use GetAstra\Models\Option;

class OptionsHelper
{

    private static $optionsCache = array();

    public function __construct()
    {
        self::loadAllOptions();
    }

    public static function clearCache(){
        self::$optionsCache = [];
    }

    public static function loadAllOptions(){
        self::$optionsCache = Option::where('autoload', 'yes')->get()->toArray();
    }

    public static function getGroupOptions($groupName){
        $groupOptions = Option::where('group', $groupName)->get()->toArray();
        self::$optionsCache = array_merge(self::$optionsCache, $groupOptions);

        $options = array();
        foreach($groupOptions as $option){
            $options[$option['name']] = $option['val'];
        }

        return $options;
    }

    public static function getAllCached(){
        $options = array();
        foreach(self::$optionsCache as $name => $option){
            $options[$name] = $option;
        }

        return $options;
    }

    public static function get($name = '' , $default = null, $allowCached = true)
    {
        $name = trim($name);

        if($allowCached && isset(self::$optionsCache[$name]['val'])){
            return self::$optionsCache[$name]['val'];
        }

        $option = Option::where('name', $name)->get()->toArray();

        if (isset($option[0]['val'])) {
            return $option[0]['val'];
        }

        if(!is_null($default)){
            return $default;
        }

        return false;
    }

    public static function add($name, $val, $autoload = 'yes', $group = 'core')
    {


        $name = trim($name);
        $data = array(
            'name' => $name,
            'val' => $val,
            'autoload' => $autoload,
            'group' => $group,
        );

        // Update cache
        self::$optionsCache[$name] = $data;

        return Option::insert($data);
    }


    public static function set($name, $val, $autoload = 'yes', $group = '')
    {
        if(is_null($val)){
            return false;
        }

        $name = trim($name);
        $option = Option::whereName($name)->first();

        if (!$option) {
            if(empty($group)){
                $group = 'core';
            }
            return self::add($name, $val, $autoload, $group);
        }

        $option->val = $val;
        $option->autoload = $autoload;

        if(!empty($group)){
            $option->group = $group;
        }

        // Update cache
        self::$optionsCache[$name] = $option->toArray();

        return $option->save();

    }

    public static function delete($name)
    {
        $name = trim($name);

        // Remove from cache
        unset(self::$optionsCache[$name]);

        return Option::destroy($name);
    }

    public static function increment($name){
        $val = self::get($name, 0, false);

        if(!$val){
            $val = 0;
        }

        self::set($name, $val + 1);
        return $val + 1;

    }
}