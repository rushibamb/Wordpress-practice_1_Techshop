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
 * @date   2019-03-10
 */

namespace GetAstra\Helpers;

class ConfigCheckHelper
{
    public static $test_files = array(
        '/webservice/dispatcher.php',
        '/bootstrap.php',
        '/vendor/autoload.php',
    );

    /**
     * getDefaultTests return an array of tests to executes.
     * key are method name, value are parameters (false for no parameter)
     * all path are ASTRAROOT related.
     *
     * @return array
     */
    public static function getDefaultTests()
    {
        $tests = array(
            'upload' => false,
            'cache_dir' => 'var/cache',
            'log_dir' => 'var/logs',
            'plugins_dir' => 'plugins',
        );

        if (!defined('_PS_HOST_MODE_')) {
            $tests = array_merge($tests, array(
                'system' => array(
                    'fopen', 'fclose', 'fread', 'fwrite',
                    'rename', 'file_exists', 'unlink', 'rmdir', 'mkdir',
                    'getcwd', 'chdir', 'chmod',
                ),
                'phpversion' => false,
                'apache_mod_rewrite' => false,
                'curl' => false,
                'json' => false,
                'pdo_mysql' => false,
                'config_dir' => 'config',
                'openssl' => 'false',
                'simplexml' => false,
                'zip' => false,
                'fileinfo' => false,
            ));
        }

        return $tests;
    }

    /**
     * getDefaultTestsOp return an array of tests to executes.
     * key are method name, value are parameters (false for no parameter).
     *
     * @return array
     */
    public static function getDefaultTestsOp()
    {
        return array(
            'new_phpversion' => false,
            'gz' => false,
            'mbstring' => false,
            'dom' => false,
            'pdo_mysql' => false,
            'fopen' => false,
            'intl' => false,
        );
    }

    /**
     * run all test defined in $tests.
     *
     * @param array $tests
     *
     * @return array results of tests
     */
    public static function check($tests)
    {
        $res = array();
        foreach ($tests as $key => $test) {
            $res[$key] = ConfigCheckHelper::run($key, $test);
        }

        return $res;
    }

    public static function run($ptr, $arg = 0)
    {
        if (call_user_func(array('ConfigCheckHelper', 'test_' . $ptr), $arg)) {
            return 'ok';
        }

        return 'fail';
    }

    public static function test_phpversion()
    {
        return version_compare(substr(PHP_VERSION, 0, 5), '5.6.0', '>=');
    }

    public static function test_apache_mod_rewrite()
    {
        if (isset($_SERVER['SERVER_SOFTWARE'])
            && strpos(strtolower($_SERVER['SERVER_SOFTWARE']), 'apache') === false || !function_exists('apache_get_modules')) {
            return true;
        }

        return in_array('mod_rewrite', apache_get_modules());
    }

    public static function test_new_phpversion()
    {
        return version_compare(substr(PHP_VERSION, 0, 5), '5.6.0', '>=');
    }

    public static function test_mysql_support()
    {
        return extension_loaded('mysql') || extension_loaded('mysqli') || extension_loaded('pdo_mysql');
    }

    public static function test_intl()
    {
        return extension_loaded('intl');
    }

    public static function test_pdo_mysql()
    {
        return extension_loaded('pdo_mysql');
    }

    public static function test_upload()
    {
        return ini_get('file_uploads');
    }

    public static function test_fopen()
    {
        return in_array(ini_get('allow_url_fopen'), array('On', 'on', '1'));
    }

    public static function test_system($funcs)
    {
        foreach ($funcs as $func) {
            if (!function_exists($func)) {
                return false;
            }
        }

        return true;
    }

    public static function test_curl()
    {
        return extension_loaded('curl');
    }

    public static function test_gd()
    {
        return function_exists('imagecreatetruecolor');
    }

    public static function test_json()
    {
        return extension_loaded('json');
    }

    public static function test_gz()
    {
        if (function_exists('gzencode')) {
            return @gzencode('dd') !== false;
        }

        return false;
    }

    public static function test_simplexml()
    {
        return extension_loaded('SimpleXML');
    }

    public static function test_zip()
    {
        return extension_loaded('zip');
    }

    public static function test_fileinfo()
    {
        return extension_loaded('fileinfo');
    }

    public static function test_dir($relative_dir, $recursive = false, &$full_report = null)
    {
        $dir = rtrim(ASTRAROOT, '\\/') . DIRECTORY_SEPARATOR . trim($relative_dir, '\\/');
        if (!file_exists($dir) || !$dh = @opendir($dir)) {
            $full_report = sprintf('Directory %s does not exist or is not writable', $dir); // sprintf for future translation
            return false;
        }
        closedir($dh);
        $dummy = rtrim($dir, '\\/') . DIRECTORY_SEPARATOR . uniqid();
        if (@file_put_contents($dummy, 'test')) {
            @unlink($dummy);
            if (!$recursive) {
                return true;
            }
        } elseif (!is_writable($dir)) {
            $full_report = sprintf('Directory %s is not writable', $dir); // sprintf for future translation
            return false;
        }

        return true;
    }

    public static function test_file($file_relative)
    {
        $file = ASTRAROOT . DIRECTORY_SEPARATOR . $file_relative;

        return file_exists($file) && is_writable($file);
    }

    public static function test_config_dir($dir)
    {
        return ConfigCheckHelper::test_dir($dir);
    }

    public static function test_sitemap($dir)
    {
        return ConfigCheckHelper::test_file($dir);
    }

    public static function test_root_dir($dir)
    {
        return ConfigCheckHelper::test_dir($dir);
    }

    public static function test_log_dir($dir)
    {
        return ConfigCheckHelper::test_dir($dir);
    }

    public static function test_admin_dir($dir)
    {
        return ConfigCheckHelper::test_dir($dir);
    }

    public static function test_img_dir($dir)
    {
        return ConfigCheckHelper::test_dir($dir, true);
    }

    public static function test_plugins_dir($dir)
    {
        return ConfigCheckHelper::test_dir($dir, true);
    }

    public static function test_cache_dir($dir)
    {
        return ConfigCheckHelper::test_dir($dir, true);
    }

    public static function test_tools_v2_dir($dir)
    {
        return ConfigCheckHelper::test_dir($dir);
    }

    public static function test_cache_v2_dir($dir)
    {
        return ConfigCheckHelper::test_dir($dir);
    }

    public static function test_download_dir($dir)
    {
        return ConfigCheckHelper::test_dir($dir);
    }

    public static function test_mails_dir($dir)
    {
        return ConfigCheckHelper::test_dir($dir, true);
    }

    public static function test_translations_dir($dir)
    {
        return ConfigCheckHelper::test_dir($dir, true);
    }

    public static function test_config_sf2_dir($dir)
    {
        return ConfigCheckHelper::test_dir($dir, true);
    }

    public static function test_theme_lang_dir($dir)
    {
        $absoluteDir = rtrim(ASTRAROOT, '\\/') . DIRECTORY_SEPARATOR . trim($dir, '\\/');
        if (!file_exists($absoluteDir)) {
            return true;
        }

        return ConfigCheckHelper::test_dir($dir, true);
    }

    public static function test_theme_pdf_lang_dir($dir)
    {
        $absoluteDir = rtrim(ASTRAROOT, '\\/') . DIRECTORY_SEPARATOR . trim($dir, '\\/');
        if (!file_exists($absoluteDir)) {
            return true;
        }

        return ConfigCheckHelper::test_dir($dir, true);
    }

    public static function test_theme_cache_dir($dir)
    {
        $absoluteDir = rtrim(ASTRAROOT, '\\/') . DIRECTORY_SEPARATOR . trim($dir, '\\/');
        if (!file_exists($absoluteDir)) {
            return true;
        }

        return ConfigCheckHelper::test_dir($dir, true);
    }

    public static function test_customizable_products_dir($dir)
    {
        return ConfigCheckHelper::test_dir($dir);
    }

    public static function test_virtual_products_dir($dir)
    {
        return ConfigCheckHelper::test_dir($dir);
    }

    public static function test_mbstring()
    {
        return function_exists('mb_strtolower');
    }

    public static function test_openssl()
    {
        return function_exists('openssl_encrypt');
    }

    public static function test_sessions()
    {
        if (!$path = @ini_get('session.save_path')) {
            return true;
        }

        return is_writable($path);
    }

    public static function test_dom()
    {
        return extension_loaded('Dom');
    }

    public static function test_files($full = false)
    {
        $return = array();
        foreach (ConfigCheckHelper::$test_files as $file) {
            if (!file_exists(rtrim(ASTRAROOT, DIRECTORY_SEPARATOR) . str_replace('/', DIRECTORY_SEPARATOR, $file))) {
                if ($full) {
                    $return[] = $file;
                } else {
                    return false;
                }
            }
        }

        if ($full) {
            return $return;
        }

        return true;
    }

    public static function test_translations_sf2($dir)
    {
        return ConfigCheckHelper::test_dir($dir);
    }
}

/*
 * // Run all tests
 * $paramsRequiredResults = ConfigurationTest::check(ConfigurationTest::getDefaultTests());
 *
 * $failRequired = in_array('fail', $paramsRequiredResults); //boolean
 *
*/