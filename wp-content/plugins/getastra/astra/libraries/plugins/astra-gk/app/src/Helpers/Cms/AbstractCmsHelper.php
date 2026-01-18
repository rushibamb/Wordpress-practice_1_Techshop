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
 * @date   2019-04-05
 */

namespace GetAstra\Helpers\Cms;


class AbstractCmsHelper
{
    private $path;
    private $cms;
    private $instance;

    public function __construct($path = '')
    {
        if (!empty($path)) {
            $this->path = $path;
        } else {
            $this->path = ASTRA_DOC_ROOT;
        }

        $this->cms = $this->detect_cms($this->path);
        $this->instance = $this->getCmsInstance($this->cms);
    }

    public function getCmsName()
    {
        return $this->cms;
    }

    public function getCms()
    {
        return $this->instance;
    }


    protected function getCmsInstance($cms, $recursion = false)
    {
        
        $className = 'GetAstra\\Helpers\\Cms\\' . ucwords($cms) . 'Helper';

        if (class_exists($className)) {
            $adapter = new $className($this->path);
            return $adapter;
        } elseif (!$recursion) {
            return $this->getCmsInstance('unknown');
        }
    }

    protected function detect_cms($path)
    {

        $mapping = array(
            "wordpress" => array('wp-load.php', 'wp-config.php', 'wp-includes/plugin.php'),
            "joomla2" => array('libraries/cms/version/version.php', 'components/com_wrapper', 'libraries/joomla'),
            "joomla3" => array('libraries/fof', 'libraries/src/Version.php', 'modules/mod_menu'),
            //"drupal" => array('modules', 'profiles', 'includes', 'sites', 'includes/cache.inc'),
            "magento19" => array('skin', 'app', 'lib'),
            "magento2" => array('app/design/adminhtml/Magento', 'lib/web'),
            "drupal7" => array('includes/bootstrap.inc', 'sites/all'),
            "opencart" => array('config.php', 'system/startup.php', 'catalog/controller'),
            "prestashop16" => array('config/smartyfront.config.inc.php', 'config/settings.inc.php', 'footer.php'),
            "prestashop17" => array('app/AppKernel.php', 'app/AppCache.php'),
            //"codeigniter" => array('system/core/CodeIgniter.php', 'system/libraries/Zip.php', 'application/config/config.php'),
        );

        foreach ($mapping as $cms_name => $files) {
            $not_found = false;

            foreach ($files as $file) {
                if (!file_exists($path . $file)) {
                    $not_found = true;
                }
            }

            if ($not_found === false) {
                return $cms_name;
            }
        }

        return 'unknown';

    }
}